"""SCA / CIS compliance scanner — Wazuh Security Configuration Assessment."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from lureguard_mcp.db import (
    get_agent_sca_last_scan_db,
    get_agent_sca_summary_db,
    get_fleet_sca_summary_db,
    replace_agent_sca_findings_db,
)
from lureguard_mcp.wazuh_client import WazuhClient

CHECK_PAGE = 500
_FAILED_RESULTS = frozenset({"failed", "fail"})


def _fetch_all_checks(wazuh: WazuhClient, agent_id: str, policy_id: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    offset = 0
    while True:
        resp = wazuh.get_sca_checks(agent_id, policy_id, limit=CHECK_PAGE, offset=offset)
        items = resp.get("data", {}).get("affected_items") or []
        checks.extend(items)
        total = resp.get("data", {}).get("total_affected_items")
        if not items:
            break
        if total is not None and offset + len(items) >= int(total):
            break
        if len(items) < CHECK_PAGE:
            break
        offset += CHECK_PAGE
    return checks


def scan_agent_sca(agent_id: str, *, wazuh: WazuhClient | None = None) -> dict[str, Any]:
    """Fetch SCA policies and checks for one agent and persist to Postgres."""
    wazuh = wazuh or WazuhClient()
    scanned_at = datetime.utcnow()

    try:
        policies_resp = wazuh.get_sca_policies(agent_id)
    except Exception as exc:
        return {"agent_id": agent_id, "error": str(exc), "findings": [], "summary": {}}

    policies = policies_resp.get("data", {}).get("affected_items") or []
    if not policies:
        replace_agent_sca_findings_db(agent_id=agent_id, findings=[], scanned_at=scanned_at)
        return {
            "agent_id": agent_id,
            "policies": 0,
            "summary": get_agent_sca_summary_db(agent_id),
            "scanned_at": scanned_at.isoformat(),
            "message": "no SCA policies reported by Wazuh",
        }

    findings: list[dict[str, Any]] = []
    for policy in policies:
        policy_id = str(policy.get("policy_id") or policy.get("id") or "")
        if not policy_id:
            continue
        policy_name = str(policy.get("name") or policy_id)
        try:
            checks = _fetch_all_checks(wazuh, agent_id, policy_id)
        except Exception:
            continue
        for check in checks:
            check_id = str(check.get("id") or check.get("check_id") or "")
            if not check_id:
                continue
            result = str(check.get("result") or "").lower()
            findings.append(
                {
                    "policy_id": policy_id,
                    "policy_name": policy_name,
                    "check_id": check_id,
                    "title": str(check.get("title") or check.get("description") or "")[:2000] or None,
                    "result": result or "unknown",
                    "compliance": check.get("compliance"),
                    "remediation": str(check.get("remediation") or "")[:4000] or None,
                }
            )

    replace_agent_sca_findings_db(agent_id=agent_id, findings=findings, scanned_at=scanned_at)
    summary = get_agent_sca_summary_db(agent_id)
    return {
        "agent_id": agent_id,
        "policies": len(policies),
        "checks_stored": len(findings),
        "summary": summary,
        "scanned_at": scanned_at.isoformat(),
        "top_failed": summary.get("top_failed", [])[:10],
    }


def get_agent_sca_summary(agent_id: str) -> dict[str, Any]:
    """Cached SCA summary for one agent."""
    summary = get_agent_sca_summary_db(agent_id)
    scanned_at = get_agent_sca_last_scan_db(agent_id)
    return {
        "agent_id": agent_id,
        "source": "postgres+wazuh_sca",
        "scanned_at": scanned_at,
        **summary,
        "hint": "Run trigger_posture_scan if data is stale or empty",
    }


def get_fleet_sca_summary() -> dict[str, Any]:
    return get_fleet_sca_summary_db()
