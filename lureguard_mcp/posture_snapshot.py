"""Unified posture snapshot — instant read from Postgres caches."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from lureguard_mcp.db import (
    get_agent_cve_counts_db,
    get_agent_cve_last_scan_db,
    get_agent_detection_coverage_db,
    get_agent_exposure_counts_db,
    get_agent_exposure_last_scan_db,
    get_host_ip_db,
)
from lureguard_mcp.detection_scanner import get_agent_detection_coverage
from lureguard_mcp.exposure_scanner import get_agent_exposure
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
    """Instant posture read from Postgres — CVE, exposure, detection coverage."""
    cve_scanned = get_agent_cve_last_scan_db(agent_id)
    exposure_scanned = get_agent_exposure_last_scan_db(agent_id)
    detection_row = get_agent_detection_coverage_db(agent_id)
    detection_scanned = detection_row.get("scanned_at") if detection_row else None

    cve_status = _pillar_status(cve_scanned)
    exposure_status = _pillar_status(exposure_scanned)
    detection_status = _pillar_status(detection_scanned)

    any_never = any(
        s["status"] == "never_scanned"
        for s in (cve_status, exposure_status, detection_status)
    )
    any_stale = any(s["stale"] for s in (cve_status, exposure_status, detection_status))

    cve_counts = get_agent_cve_counts_db(agent_id, actionable_only=True)
    exposure_counts = get_agent_exposure_counts_db(agent_id)
    risky_exposure = sum(
        exposure_counts.get(level, 0) for level in ("critical", "high", "medium")
    )

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

    return {
        "agent_id": agent_id,
        "agent_ip": get_host_ip_db(agent_id),
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
                "note": "Counts are actionable CVEs only (patched/noise filtered)",
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
        },
        "top_actionable_cves": get_agent_vulnerabilities(
            agent_id, actionable_only=True, limit=10
        ).get("findings", []),
        "top_risky_ports": get_agent_exposure(
            agent_id, risk_level="critical", limit=5
        ).get("findings", [])
        or get_agent_exposure(agent_id, risk_level="high", limit=5).get("findings", []),
        "detection": get_agent_detection_coverage(agent_id),
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
                "cve_total": snap["pillars"]["vulnerabilities"]["total"],
                "exposure_total": snap["pillars"]["exposure"]["total"],
                "alerts_24h": snap["pillars"]["detection_coverage"].get("alerts_24h"),
            }
        )
    return {
        "fleet": snapshots,
        "agents_needing_rescan": sum(1 for s in snapshots if s["needs_rescan"]),
    }
