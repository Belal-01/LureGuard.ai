"""Background posture scan scheduler — CVE, exposure, detection, SCA, users."""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable

from apscheduler.schedulers.background import BackgroundScheduler

from lureguard_mcp.db import (
    create_posture_scan_job_db,
    get_posture_scan_job_db,
    update_posture_scan_job_db,
)
from lureguard_mcp.container_posture import scan_agent_containers
from lureguard_mcp.detection_scanner import scan_agent_detection_coverage
from lureguard_mcp.exposure_scanner import scan_agent_exposure
from lureguard_mcp.posture_snapshot import get_posture_snapshot
from lureguard_mcp.sca_scanner import scan_agent_sca
from lureguard_mcp.user_scanner import scan_agent_users
from lureguard_mcp.vuln_scanner import scan_agent_vulnerabilities
from lureguard_mcp.alert_watcher import start_alert_watcher
from lureguard_mcp.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)

SCAN_INTERVAL_HOURS = 6
ESTIMATED_MINUTES_PER_AGENT = 5
SCAN_STEPS = (
    "vulnerabilities",
    "exposure",
    "detection_coverage",
    "sca_compliance",
    "user_inventory",
    "containers",
)

_scheduler: BackgroundScheduler | None = None
_scan_lock = threading.Lock()
_active_jobs: dict[str, dict[str, Any]] = {}
_wazuh = WazuhClient()


def _list_active_agent_ids() -> list[str]:
    try:
        resp = _wazuh.list_agents(status="active", limit=500)
        ids: list[str] = []
        for agent in resp.get("data", {}).get("affected_items") or []:
            aid = str(agent.get("id", ""))
            if aid and aid != "000":
                ids.append(aid)
        return ids
    except Exception as exc:
        logger.warning("Failed to list agents for posture scan: %s", exc)
        return []


def _filter_agents_for_scan(agent_ids: list[str], *, force: bool) -> list[str]:
    if force:
        return agent_ids
    return [aid for aid in agent_ids if get_posture_snapshot(aid).get("needs_rescan")]


def _scan_one_agent(
    agent_id: str,
    *,
    on_step_start: Callable[[str, str], None] | None = None,
    on_step_done: Callable[[str, str, Any], None] | None = None,
) -> dict[str, Any]:
    results: dict[str, Any] = {"agent_id": agent_id, "started_at": datetime.utcnow().isoformat()}
    scanners = (
        ("vulnerabilities", scan_agent_vulnerabilities),
        ("exposure", scan_agent_exposure),
        ("detection_coverage", scan_agent_detection_coverage),
        ("sca_compliance", scan_agent_sca),
        ("user_inventory", scan_agent_users),
        ("containers", scan_agent_containers),
    )
    for key, fn in scanners:
        if on_step_start is not None:
            on_step_start(agent_id, key)
        try:
            results[key] = fn(agent_id, wazuh=_wazuh)
        except Exception as exc:
            results[key] = {"error": str(exc)}
        finally:
            if on_step_done is not None:
                on_step_done(agent_id, key, results.get(key))
    results["completed_at"] = datetime.utcnow().isoformat()
    return results


def _run_posture_scan(agent_ids: list[str], job_id: str) -> None:
    with _scan_lock:
        if job_id in _active_jobs:
            _active_jobs[job_id]["status"] = "running"
            _active_jobs[job_id]["agents_total"] = len(agent_ids)
    update_posture_scan_job_db(job_id, status="running", agents_completed=0)

    completed = 0
    completed_steps = 0
    total_steps = max(1, len(agent_ids) * len(SCAN_STEPS))
    results: dict[str, Any] = {
        "_meta": {
            "total_steps": total_steps,
            "completed_steps": 0,
            "progress_percent": 0.0,
            "current_agent": None,
            "current_step": None,
            "updated_at": datetime.utcnow().isoformat(),
        }
    }
    error: str | None = None

    def _persist_progress(current_agent: str | None, current_step: str | None) -> None:
        progress_percent = round((completed_steps * 100.0) / total_steps, 1)
        meta = {
            "total_steps": total_steps,
            "completed_steps": completed_steps,
            "progress_percent": progress_percent,
            "current_agent": current_agent,
            "current_step": current_step,
            "updated_at": datetime.utcnow().isoformat(),
        }
        results["_meta"] = meta
        with _scan_lock:
            if job_id in _active_jobs:
                _active_jobs[job_id]["progress"] = meta
        update_posture_scan_job_db(
            job_id,
            status="running",
            agents_completed=completed,
            results=results,
        )

    def _on_step_done(agent_id: str, step_key: str, _step_result: Any) -> None:
        nonlocal completed_steps
        completed_steps += 1
        _persist_progress(agent_id, step_key)

    def _on_step_start(agent_id: str, step_key: str) -> None:
        _persist_progress(agent_id, step_key)

    try:
        for aid in agent_ids:
            _persist_progress(aid, None)
            result = _scan_one_agent(
                aid,
                on_step_start=_on_step_start,
                on_step_done=_on_step_done,
            )
            completed += 1
            results[aid] = result
            with _scan_lock:
                if job_id in _active_jobs:
                    _active_jobs[job_id]["agents_completed"] = completed
                    _active_jobs[job_id]["results"][aid] = result
            _persist_progress(aid, None)
        final_status = "completed"
    except Exception as exc:
        error = str(exc)
        final_status = "failed"
        logger.exception("Posture scan job %s failed: %s", job_id, exc)

    finished = datetime.utcnow().isoformat()
    with _scan_lock:
        if job_id in _active_jobs:
            _active_jobs[job_id]["status"] = final_status
            _active_jobs[job_id]["finished_at"] = finished
            if error:
                _active_jobs[job_id]["error"] = error
    if final_status == "completed":
        completed_steps = total_steps
        results["_meta"] = {
            "total_steps": total_steps,
            "completed_steps": completed_steps,
            "progress_percent": 100.0,
            "current_agent": None,
            "current_step": None,
            "updated_at": datetime.utcnow().isoformat(),
        }

    update_posture_scan_job_db(
        job_id,
        status=final_status,
        agents_completed=completed,
        results=results,
        error=error,
        completed=True,
    )


def _start_job(agent_ids: list[str], *, trigger: str, single_agent: str = "") -> dict[str, Any]:
    if not agent_ids:
        return {"status": "error", "error": "no agents to scan (cache may be fresh — use force=true)"}

    job_id = str(uuid.uuid4())[:8]
    create_posture_scan_job_db(
        job_id=job_id,
        agent_ids=agent_ids,
        trigger=trigger,
        agent_id=single_agent or None,
    )
    with _scan_lock:
        _active_jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "trigger": trigger,
            "agent_ids": agent_ids,
            "agents_total": len(agent_ids),
            "agents_completed": 0,
            "progress": {
                "total_steps": max(1, len(agent_ids) * len(SCAN_STEPS)),
                "completed_steps": 0,
                "progress_percent": 0.0,
                "current_agent": None,
                "current_step": None,
                "updated_at": datetime.utcnow().isoformat(),
            },
            "results": {},
            "started_at": datetime.utcnow().isoformat(),
        }

    thread = threading.Thread(
        target=_run_posture_scan,
        args=(agent_ids, job_id),
        name=f"posture-scan-{job_id}",
        daemon=True,
    )
    thread.start()

    est_minutes = max(1, len(agent_ids) * ESTIMATED_MINUTES_PER_AGENT)
    return {
        "status": "scan_started",
        "job_id": job_id,
        "agent_ids": agent_ids,
        "agents_total": len(agent_ids),
        "estimated_minutes": est_minutes,
        "message": (
            f"Background scan started for {len(agent_ids)} agent(s). "
            f"Use get_posture_snapshot after ~{est_minutes} min."
        ),
    }


def _scan_all_agents() -> None:
    agent_ids = _list_active_agent_ids()
    if not agent_ids:
        logger.info("Posture scan skipped — no active agents")
        return
    job_id = f"scheduled-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    create_posture_scan_job_db(job_id=job_id, agent_ids=agent_ids, trigger="scheduler")
    with _scan_lock:
        _active_jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "trigger": "scheduler",
            "agents_total": len(agent_ids),
            "agents_completed": 0,
            "progress": {
                "total_steps": max(1, len(agent_ids) * len(SCAN_STEPS)),
                "completed_steps": 0,
                "progress_percent": 0.0,
                "current_agent": None,
                "current_step": None,
                "updated_at": datetime.utcnow().isoformat(),
            },
            "results": {},
            "started_at": datetime.utcnow().isoformat(),
        }
    thread = threading.Thread(
        target=_run_posture_scan,
        args=(agent_ids, job_id),
        name=f"posture-scan-{job_id}",
        daemon=True,
    )
    thread.start()
    logger.info("Scheduled posture scan started job_id=%s agents=%s", job_id, len(agent_ids))


def trigger_posture_scan(agent_id: str = "", force: bool = False) -> dict[str, Any]:
    """Queue a background posture scan. Returns immediately."""
    running_job = _get_latest_running_job()
    if running_job:
        return {
            "status": "already_running",
            "job_id": running_job["job_id"],
            "message": "A posture scan is already running. Wait for completion before starting another.",
        }

    if agent_id.strip():
        agent_ids = [agent_id.strip()]
        single = agent_id.strip()
    else:
        agent_ids = _list_active_agent_ids()
        single = ""

    if not agent_ids:
        return {"status": "error", "error": "no active agents to scan"}

    if not force:
        agent_ids = _filter_agents_for_scan(agent_ids, force=False)

    return _start_job(agent_ids, trigger="manual", single_agent=single)


def _get_latest_running_job() -> dict[str, Any] | None:
    """Return most recent non-stale running posture scan job from DB, if any."""
    from lureguard_mcp.db import get_conn
    import psycopg2.extras

    stale_cutoff = datetime.utcnow() - timedelta(minutes=20)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT job_id, status, started_at, results
                FROM posture_scan_jobs
                WHERE status = 'running'
                ORDER BY started_at DESC
                LIMIT 10
                """
            )
            for row in cur.fetchall():
                data = dict(row)
                meta = (data.get("results") or {}).get("_meta", {}) if isinstance(data.get("results"), dict) else {}
                updated_at_raw = meta.get("updated_at")
                if updated_at_raw:
                    try:
                        updated_at = datetime.fromisoformat(str(updated_at_raw).replace("Z", "+00:00"))
                        if updated_at.tzinfo is not None:
                            updated_at = updated_at.replace(tzinfo=None)
                        if updated_at >= stale_cutoff:
                            return data
                    except ValueError:
                        continue
                # No progress heartbeat: treat as stale if started long ago.
                started_at = data.get("started_at")
                if hasattr(started_at, "replace"):
                    started_naive = started_at.replace(tzinfo=None) if getattr(started_at, "tzinfo", None) else started_at
                    if started_naive >= stale_cutoff:
                        return data
            return None


def get_scan_job_status(job_id: str) -> dict[str, Any]:
    db_job = get_posture_scan_job_db(job_id)
    if db_job:
        return db_job
    with _scan_lock:
        job = _active_jobs.get(job_id)
        if not job:
            return {"error": f"job {job_id} not found"}
        return dict(job)


def start_scan_scheduler() -> None:
    """Start APScheduler for periodic posture scans (idempotent)."""
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        _scan_all_agents,
        "interval",
        hours=SCAN_INTERVAL_HOURS,
        id="posture_scan",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("Posture scan scheduler started (every %sh)", SCAN_INTERVAL_HOURS)
    start_alert_watcher()


def stop_scan_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
