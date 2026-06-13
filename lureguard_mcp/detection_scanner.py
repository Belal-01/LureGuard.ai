"""Detection coverage scanner — FIM, rootcheck, alert volume, rule activity."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from lureguard_mcp.db import (
    count_agent_alerts_24h_db,
    get_agent_channels_active_24h_db,
    get_agent_detection_coverage_db,
    get_agent_events_last_at_db,
    get_agent_rules_firing_24h_db,
    get_fleet_detection_coverage_db,
    get_host_ip_db,
    upsert_detection_coverage_db,
)
from lureguard_mcp.wazuh_client import WazuhClient


def _module_has_data(resp: dict) -> bool:
    items = resp.get("data", {}).get("affected_items") or []
    total = resp.get("data", {}).get("total_affected_items")
    if items:
        return True
    if total is not None and int(total) > 0:
        return True
    return False


def _check_syscheck(wazuh: WazuhClient, agent_id: str) -> bool:
    try:
        return _module_has_data(wazuh.get_syscheck_results(agent_id, limit=1))
    except httpx.HTTPStatusError:
        return False
    except Exception:
        return False


def _check_rootcheck(wazuh: WazuhClient, agent_id: str) -> bool:
    try:
        return _module_has_data(wazuh.get_rootcheck_results(agent_id, limit=1))
    except httpx.HTTPStatusError:
        return False
    except Exception:
        return False


def scan_agent_detection_coverage(
    agent_id: str,
    *,
    wazuh: WazuhClient | None = None,
) -> dict[str, Any]:
    """Assess detection coverage for one agent and persist to Postgres."""
    wazuh = wazuh or WazuhClient()
    scanned_at = datetime.utcnow()
    agent_ip = get_host_ip_db(agent_id)

    fim_enabled = _check_syscheck(wazuh, agent_id)
    rootcheck_enabled = _check_rootcheck(wazuh, agent_id)
    alerts_24h = count_agent_alerts_24h_db(agent_id, agent_ip)
    rules_firing = get_agent_rules_firing_24h_db(agent_id, agent_ip, limit=25)
    channels_active = get_agent_channels_active_24h_db(agent_id, agent_ip)
    events_last_at = get_agent_events_last_at_db(agent_id, agent_ip)

    if not fim_enabled and channels_active.get("syscheck", 0) > 0:
        fim_enabled = True
    if not rootcheck_enabled and channels_active.get("rootcheck", 0) > 0:
        rootcheck_enabled = True

    firing_count = len(rules_firing)

    upsert_detection_coverage_db(
        agent_id=agent_id,
        fim_enabled=fim_enabled,
        rootcheck_enabled=rootcheck_enabled,
        alerts_24h=alerts_24h,
        rules_firing=rules_firing,
        rules_firing_count=firing_count,
        events_last_at=events_last_at,
        channels_active=channels_active,
        scanned_at=scanned_at,
    )

    return {
        "agent_id": agent_id,
        "agent_ip": agent_ip,
        "fim_enabled": fim_enabled,
        "rootcheck_enabled": rootcheck_enabled,
        "alerts_24h": alerts_24h,
        "rules_firing_count": firing_count,
        "rules_firing": rules_firing[:10],
        "events_last_at": events_last_at.isoformat() if events_last_at else None,
        "channels_active": channels_active,
        "scanned_at": scanned_at.isoformat(),
    }


def get_agent_detection_coverage(agent_id: str) -> dict[str, Any]:
    row = get_agent_detection_coverage_db(agent_id)
    if not row:
        return {
            "agent_id": agent_id,
            "source": "postgres+events",
            "scanned_at": None,
            "error": "not scanned — run trigger_posture_scan",
            "hint": "Run trigger_posture_scan if data is stale or empty",
        }
    return {
        "agent_id": agent_id,
        "source": "postgres+events",
        **row,
        "hint": "Run trigger_posture_scan if data is stale or empty",
    }


def get_fleet_detection_coverage() -> dict[str, Any]:
    return get_fleet_detection_coverage_db()
