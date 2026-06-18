"""Background posture scan scheduler — CVE, exposure, detection, SCA, users."""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler

from lureguard_mcp.db import (
    create_posture_scan_job_db,
    get_posture_scan_job_db,
    update_posture_scan_job_db,
)
from lureguard_mcp.detection_scanner import scan_agent_detection_coverage
from lureguard_mcp.exposure_scanner import scan_agent_exposure
from lureguard_mcp.posture_snapshot import get_posture_snapshot
from lureguard_mcp.sca_scanner import scan_agent_sca
from lureguard_mcp.user_scanner import scan_agent_users
from lureguard_mcp.vuln_scanner import scan_agent_vulnerabilities
from lureguard_mcp.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)

SCAN_INTERVAL_HOURS = 6
ESTIMATED_MINUTES_PER_AGENT = 5

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


def _scan_one_agent(agent_id: str) -> dict[str, Any]:
    results: dict[str, Any] = {"agent_id": agent_id, "started_at": datetime.utcnow().isoformat()}
    scanners = (
        ("vulnerabilities", scan_agent_vulnerabilities),
        ("exposure", scan_agent_exposure),
        ("detection_coverage", scan_agent_detection_coverage),
        ("sca_compliance", scan_agent_sca),
        ("user_inventory", scan_agent_users),
    )
    for key, fn in scanners:
        try:
            results[key] = fn(agent_id, wazuh=_wazuh)
        except Exception as exc:
            results[key] = {"error": str(exc)}
    results["completed_at"] = datetime.utcnow().isoformat()
    return results


def _run_posture_scan(agent_ids: list[str], job_id: str) -> None:
    with _scan_lock:
        if job_id in _active_jobs:
            _active_jobs[job_id]["status"] = "running"
            _active_jobs[job_id]["agents_total"] = len(agent_ids)
    update_posture_scan_job_db(job_id, status="running", agents_completed=0)

    completed = 0
    results: dict[str, Any] = {}
    error: str | None = None
    try:
        for aid in agent_ids:
            result = _scan_one_agent(aid)
            completed += 1
            results[aid] = result
            with _scan_lock:
                if job_id in _active_jobs:
                    _active_jobs[job_id]["agents_completed"] = completed
                    _active_jobs[job_id]["results"][aid] = result
            update_posture_scan_job_db(
                job_id,
                agents_completed=completed,
                results=results,
            )
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


def stop_scan_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
