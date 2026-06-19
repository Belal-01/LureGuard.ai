"""Unified posture snapshot — instant read from Postgres caches."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from lureguard_mcp.container_posture import get_agent_container_posture
from lureguard_mcp.db import (
    get_agent_cve_counts_db,
    get_agent_cve_last_scan_db,
    get_agent_detection_coverage_db,
    get_agent_exposure_counts_db,
    get_agent_exposure_last_scan_db,
    get_agent_sca_last_scan_db,
    get_agent_sca_summary_db,
    get_agent_user_last_scan_db,
    get_agent_user_risk_counts_db,
    get_container_cve_counts_db,
    get_container_cve_last_scan_db,
    get_host_eol_os_db,
    get_host_ip_db,
)
from lureguard_mcp.detection_scanner import get_agent_detection_coverage
from lureguard_mcp.exposure_scanner import get_agent_exposure
from lureguard_mcp.sca_scanner import get_agent_sca_summary
from lureguard_mcp.user_scanner import get_agent_users
from lureguard_mcp.vuln_scanner import get_agent_vulnerabilities

CACHE_STALE_HOURS = 24


def _cache_age_hours(scanned_at: str | None) -> float | None:
    if not scanned_at:
        return None
    try:
        ts = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
        if ts.tzinfo:
            ts = ts.replace(tzinfo=None)
        delta = datetime.utcnow() - ts
        return round(delta.total_seconds() / 3600, 1)
    except (TypeError, ValueError):
        return None


def _pillar_status(scanned_at: str | None) -> dict[str, Any]:
    age = _cache_age_hours(scanned_at)
    if scanned_at is None:
        return {
            "scanned_at": None,
            "cache_age_hours": None,
            "status": "never_scanned",
            "stale": True,
        }
    stale = age is not None and age > CACHE_STALE_HOURS
    return {
        "scanned_at": scanned_at,
        "cache_age_hours": age,
        "status": "stale" if stale else "fresh",
        "stale": stale,
    }


def get_posture_snapshot(agent_id: str) -> dict[str, Any]:
    """Instant posture read from Postgres — six pillars from cache."""
    cve_scanned = get_agent_cve_last_scan_db(agent_id)
    exposure_scanned = get_agent_exposure_last_scan_db(agent_id)
    detection_row = get_agent_detection_coverage_db(agent_id)
    detection_scanned = detection_row.get("scanned_at") if detection_row else None
    sca_scanned = get_agent_sca_last_scan_db(agent_id)
    user_scanned = get_agent_user_last_scan_db(agent_id)
    container_scanned = get_container_cve_last_scan_db(agent_id)

    cve_status = _pillar_status(cve_scanned)
    exposure_status = _pillar_status(exposure_scanned)
    detection_status = _pillar_status(detection_scanned)
    sca_status = _pillar_status(sca_scanned)
    user_status = _pillar_status(user_scanned)
    container_status = _pillar_status(container_scanned)

    pillar_statuses = (
        cve_status,
        exposure_status,
        detection_status,
        sca_status,
        user_status,
        container_status,
    )
    any_never = any(s["status"] == "never_scanned" for s in pillar_statuses)
    any_stale = any(s["stale"] for s in pillar_statuses)

    cve_counts = get_agent_cve_counts_db(agent_id, actionable_only=True)
    exposure_counts = get_agent_exposure_counts_db(agent_id)
    risky_exposure = sum(
        exposure_counts.get(level, 0) for level in ("critical", "high", "medium")
    )
    sca_summary = get_agent_sca_summary_db(agent_id)
    user_counts = get_agent_user_risk_counts_db(agent_id)
    risky_users = sum(user_counts.get(k, 0) for k in ("critical", "high", "medium"))
    container_counts = get_container_cve_counts_db(agent_id)
    container_posture = get_agent_container_posture(agent_id, limit=10)

    detection_summary: dict[str, Any] = {}
    if detection_row:
        detection_summary = {
            "fim_enabled": detection_row.get("fim_enabled"),
            "rootcheck_enabled": detection_row.get("rootcheck_enabled"),
            "alerts_24h": detection_row.get("alerts_24h"),
            "rules_firing_count": detection_row.get("rules_firing_count"),
            "events_last_at": detection_row.get("events_last_at"),
            "channels_active": detection_row.get("channels_active"),
            "rules_firing": (detection_row.get("rules_firing") or [])[:5],
        }

    users_detail = get_agent_users(agent_id, risk_level="critical", limit=5)
    if not users_detail.get("findings"):
        users_detail = get_agent_users(agent_id, risk_level="medium", limit=5)

    return {
        "agent_id": agent_id,
        "agent_ip": get_host_ip_db(agent_id),
        "eol_os": get_host_eol_os_db(agent_id),
        "source": "postgres_cache",
        "cache_policy_hours": CACHE_STALE_HOURS,
        "overall_status": "never_scanned" if any_never else ("stale" if any_stale else "fresh"),
        "needs_rescan": any_never or any_stale,
        "recommendation": (
            "Call trigger_posture_scan(agent_id) — scans run in background (~5 min)"
            if any_never or any_stale
            else "Cache is fresh — no scan required"
        ),
        "pillars": {
            "vulnerabilities": {
                **cve_status,
                "counts": cve_counts,
                "total": sum(cve_counts.values()),
                "note": "Counts are actionable CVEs only (patched/noise filtered; EPSS + EOL aware)",
            },
            "exposure": {
                **exposure_status,
                "counts": exposure_counts,
                "total": sum(exposure_counts.values()),
                "risky_listening": risky_exposure,
            },
            "detection_coverage": {
                **detection_status,
                **detection_summary,
            },
            "sca_compliance": {
                **sca_status,
                "score_percent": sca_summary.get("score_percent"),
                "failed_count": sca_summary.get("failed_count", 0),
                "counts": sca_summary.get("counts", {}),
                "top_failed": sca_summary.get("top_failed", [])[:5],
            },
            "user_inventory": {
                **user_status,
                "counts": user_counts,
                "risky_users": risky_users,
                "top_risky": users_detail.get("findings", [])[:5],
            },
            "containers": {
                **container_status,
                "counts": container_counts,
                "total_cves": sum(container_counts.values()),
                "running": container_posture.get("containers", []),
                "top_findings": container_posture.get("findings", [])[:5],
            },
        },
        "top_actionable_cves": get_agent_vulnerabilities(
            agent_id, actionable_only=True, limit=10
        ).get("findings", []),
        "top_risky_ports": get_agent_exposure(
            agent_id, risk_level="critical", limit=5
        ).get("findings", [])
        or get_agent_exposure(agent_id, risk_level="high", limit=5).get("findings", []),
        "detection": get_agent_detection_coverage(agent_id),
        "sca": get_agent_sca_summary(agent_id),
        "users": get_agent_users(agent_id, limit=20),
    }


def get_fleet_posture_summary() -> dict[str, Any]:
    """Fleet-level posture status from caches."""
    from lureguard_mcp.db import list_hosts_db

    hosts = list_hosts_db()
    snapshots = []
    for host in hosts:
        aid = str(host.get("agent_id", ""))
        if aid == "000":
            continue
        snap = get_posture_snapshot(aid)
        snapshots.append(
            {
                "agent_id": aid,
                "name": host.get("name"),
                "ip": host.get("ip"),
                "overall_status": snap["overall_status"],
                "needs_rescan": snap["needs_rescan"],
                "eol_os": snap.get("eol_os"),
                "cve_total": snap["pillars"]["vulnerabilities"]["total"],
                "exposure_total": snap["pillars"]["exposure"]["total"],
                "sca_score_percent": snap["pillars"]["sca_compliance"].get("score_percent"),
                "risky_users": snap["pillars"]["user_inventory"].get("risky_users"),
                "container_cves": snap["pillars"]["containers"]["total_cves"],
                "alerts_24h": snap["pillars"]["detection_coverage"].get("alerts_24h"),
            }
        )
    return {
        "fleet": snapshots,
        "agents_needing_rescan": sum(1 for s in snapshots if s["needs_rescan"]),
        "agents_eol_os": sum(1 for s in snapshots if s.get("eol_os")),
    }
