"""User / account inventory scanner — syscollector local users."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from lureguard_mcp.db import (
    get_agent_user_findings_db,
    get_agent_user_last_scan_db,
    get_agent_user_risk_counts_db,
    replace_agent_user_findings_db,
)
from lureguard_mcp.wazuh_client import WazuhClient

USER_PAGE = 500
_NOLOGIN_SHELLS = frozenset({"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"})


def _is_interactive_shell(shell: str) -> bool:
    s = (shell or "").strip().lower()
    if not s or s in _NOLOGIN_SHELLS:
        return False
    return True


def _score_user(username: str, uid: int | None, shell: str, last_login: str | None) -> str:
    name = (username or "").lower()
    if uid == 0 and name != "root":
        return "critical"
    if not _is_interactive_shell(shell):
        return "info"
    login = (last_login or "").strip().lower()
    if not login or login in {"never", "n/a", "-", ""}:
        return "medium"
    return "info"


def _normalize_wazuh_user(item: dict[str, Any]) -> dict[str, Any] | None:
    """Flatten Wazuh syscollector user row (fields live under item['user'])."""
    user = item.get("user") if isinstance(item.get("user"), dict) else item
    if not isinstance(user, dict):
        return None
    username = str(user.get("name") or user.get("username") or "").strip()
    if not username:
        return None
    uid_raw = user.get("id", user.get("uid"))
    gid_raw = user.get("group_id", user.get("gid"))
    try:
        uid = int(uid_raw) if uid_raw is not None else None
    except (TypeError, ValueError):
        uid = None
    try:
        gid = int(gid_raw) if gid_raw is not None else None
    except (TypeError, ValueError):
        gid = None
    shell = str(user.get("shell") or "")
    login = item.get("login") if isinstance(item.get("login"), dict) else {}
    last_login = str(item.get("last_login") or item.get("login_time") or "").strip() or None
    if not last_login and login.get("status") not in (None, 0, "0", ""):
        last_login = "active"
    return {
        "username": username,
        "uid": uid,
        "gid": gid,
        "shell": shell or None,
        "last_login": last_login,
    }


def _fetch_all_users(wazuh: WazuhClient, agent_id: str) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    offset = 0
    while True:
        resp = wazuh.get_agent_users(agent_id, limit=USER_PAGE, offset=offset)
        items = resp.get("data", {}).get("affected_items") or []
        users.extend(items)
        total = resp.get("data", {}).get("total_affected_items")
        if not items:
            break
        if total is not None and offset + len(items) >= int(total):
            break
        if len(items) < USER_PAGE:
            break
        offset += USER_PAGE
    return users


def scan_agent_users(agent_id: str, *, wazuh: WazuhClient | None = None) -> dict[str, Any]:
    """Fetch local users for one agent and persist risk-scored inventory."""
    wazuh = wazuh or WazuhClient()
    scanned_at = datetime.utcnow()

    try:
        raw_users = _fetch_all_users(wazuh, agent_id)
    except Exception as exc:
        return {"agent_id": agent_id, "error": str(exc), "findings": [], "counts": {}}

    findings: list[dict[str, Any]] = []
    for item in raw_users:
        normalized = _normalize_wazuh_user(item)
        if not normalized:
            continue
        risk = _score_user(
            normalized["username"],
            normalized["uid"],
            normalized["shell"] or "",
            normalized["last_login"],
        )
        findings.append({**normalized, "risk_level": risk})

    replace_agent_user_findings_db(agent_id=agent_id, findings=findings, scanned_at=scanned_at)
    counts = get_agent_user_risk_counts_db(agent_id)
    risky = [f for f in findings if f.get("risk_level") in {"critical", "high", "medium"}]
    return {
        "agent_id": agent_id,
        "users_scanned": len(findings),
        "risky_users": len(risky),
        "counts": counts,
        "scanned_at": scanned_at.isoformat(),
        "findings": sorted(
            findings,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                str(f.get("risk_level")), 5
            ),
        )[:100],
        "truncated": len(findings) > 100,
    }


def get_agent_users(agent_id: str, *, risk_level: str | None = None, limit: int = 500) -> dict[str, Any]:
    """Cached user inventory for one agent."""
    items = get_agent_user_findings_db(agent_id, risk_level=risk_level, limit=limit)
    counts = get_agent_user_risk_counts_db(agent_id)
    scanned_at = get_agent_user_last_scan_db(agent_id)
    return {
        "agent_id": agent_id,
        "source": "postgres+syscollector",
        "scanned_at": scanned_at,
        "counts": counts,
        "total": sum(counts.values()),
        "risky_total": sum(counts.get(k, 0) for k in ("critical", "high", "medium")),
        "findings": items,
        "hint": "Run trigger_posture_scan if data is stale or empty",
    }
