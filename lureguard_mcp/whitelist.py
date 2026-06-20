"""IP whitelist — recommend, confirm (human-approved), list/remove."""

from __future__ import annotations

import json
from typing import Any

from lureguard_mcp.config import allow_agent_whitelist
from lureguard_mcp.db import (
    add_whitelist_db,
    confirm_whitelist_db,
    get_whitelist_entry_db,
    list_whitelist_db,
    remove_whitelist_db,
)
from lureguard_mcp.ssh_remote import SSHValidationError, validate_ip


def recommend_whitelist_ip(
    ip: str,
    reason: str,
    investigation_id: str = "",
) -> dict[str, Any]:
    try:
        validate_ip(ip, field="ip")
    except SSHValidationError as exc:
        return {"status": "error", "error": str(exc)}

    entry = add_whitelist_db(
        ip=ip,
        reason=reason,
        investigation_id=investigation_id or None,
        added_by="agent",
        executed=False,
    )
    entry["confirm_command"] = (
        f"confirm_whitelist_ip(whitelist_id='{entry['whitelist_id']}')"
    )
    entry["note"] = (
        "Core ML picks up active whitelist entries on the next scheduler tick (~2s)."
    )
    return entry


def confirm_whitelist_ip(
    whitelist_id: str,
    notes: str = "",
    *,
    caller: str = "human",
) -> dict[str, Any]:
    if caller != "human" and not allow_agent_whitelist():
        return {
            "status": "denied",
            "error": (
                "confirm_whitelist_ip requires human approval. "
                "Set LUREGUARD_ALLOW_AGENT_WHITELIST=true only for testing."
            ),
        }

    entry = get_whitelist_entry_db(whitelist_id)
    if not entry:
        return {"status": "error", "error": f"whitelist_id {whitelist_id} not found"}
    if entry.get("executed"):
        return {
            "status": "already_active",
            "whitelist_id": whitelist_id,
            "ip": entry.get("ip"),
        }

    confirmed = confirm_whitelist_db(
        whitelist_id,
        notes=notes or "human confirmed — SSH ML will skip alert/redirect for this IP",
    )
    return {
        "status": "active",
        "whitelist_id": whitelist_id,
        "ip": confirmed.get("ip") if confirmed else entry.get("ip"),
        "whitelist": confirmed,
        "note": "Core refreshes whitelist from Postgres every ~2s.",
    }


def list_whitelist(pending_only: bool = False) -> str:
    rows = list_whitelist_db(pending_only=pending_only)
    return json.dumps({"count": len(rows), "entries": rows}, indent=2)


def remove_whitelist_ip(
    whitelist_id: str = "",
    ip: str = "",
    *,
    caller: str = "human",
) -> dict[str, Any]:
    if caller != "human" and not allow_agent_whitelist():
        return {
            "status": "denied",
            "error": (
                "remove_whitelist_ip requires human approval. "
                "Set LUREGUARD_ALLOW_AGENT_WHITELIST=true only for testing."
            ),
        }

    if not whitelist_id and not ip:
        return {"status": "error", "error": "provide whitelist_id or ip"}
    if ip:
        try:
            validate_ip(ip, field="ip")
        except SSHValidationError as exc:
            return {"status": "error", "error": str(exc)}
    removed = remove_whitelist_db(whitelist_id=whitelist_id, ip=ip)
    if not removed:
        return {"status": "error", "error": "whitelist entry not found"}
    return {"status": "removed", "whitelist_id": whitelist_id or None, "ip": ip or None}
