"""IP blocklist — recommend, confirm (human-approved), execute via iptables."""

from __future__ import annotations

import json
import logging
from typing import Any

from lureguard_mcp.config import allow_agent_block, onboard_ssh_password
from lureguard_mcp.db import (
    add_blocklist_db,
    confirm_blocklist_db,
    get_agent_ids_for_src_ip_db,
    get_blocklist_entry_db,
    list_blocklist_db,
    list_hosts_db,
)
from lureguard_mcp.secrets import redact_ssh_output
from lureguard_mcp.ssh_remote import (
    SSHValidationError,
    build_sudo_remote_command,
    run_remote_shell,
    validate_ip,
)

logger = logging.getLogger(__name__)


def recommend_block_ip(
    ip: str,
    reason: str,
    investigation_id: str = "",
) -> dict[str, Any]:
    try:
        validate_ip(ip, field="ip")
    except SSHValidationError as exc:
        return {"status": "error", "error": str(exc)}

    entry = add_blocklist_db(
        ip=ip,
        reason=reason,
        investigation_id=investigation_id or None,
        added_by="agent",
    )
    entry["confirm_command"] = f"confirm_block_ip(block_id='{entry['block_id']}')"
    return entry


def _ssh_iptables_drop(host_ip: str, block_ip: str, password: str) -> dict[str, Any]:
    try:
        host = validate_ip(host_ip, field="host_ip")
        block = validate_ip(block_ip, field="block_ip")
    except SSHValidationError as exc:
        return {"host": host_ip, "ok": False, "error": str(exc)}

    inner = (
        f"iptables -C INPUT -s {block} -j DROP 2>/dev/null "
        f"|| iptables -I INPUT -s {block} -j DROP"
    )
    remote = build_sudo_remote_command(password, inner)
    result = run_remote_shell(host, remote, password=password, timeout=30)
    return {
        "host": host,
        "ok": result.get("ok", False),
        "stdout": redact_ssh_output(result.get("stdout", "")),
        "stderr": redact_ssh_output(result.get("stderr", "")),
        "error": result.get("error"),
    }


def _active_hosts() -> list[dict[str, Any]]:
    return [h for h in list_hosts_db() if h.get("wazuh_status") == "active" and h.get("ip")]


def _resolve_block_hosts(
    block_ip: str,
    *,
    agent_id: str = "",
    fleet_wide: bool = False,
    window_hours: int = 48,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if fleet_wide:
        return _active_hosts(), None

    if agent_id:
        hosts = [
            h
            for h in _active_hosts()
            if str(h.get("agent_id")) == agent_id.strip()
        ]
        if not hosts:
            return [], {
                "status": "error",
                "error": f"agent_id {agent_id} not found among active enrolled hosts",
            }
        return hosts, None

    agent_ids = set(get_agent_ids_for_src_ip_db(block_ip, window_hours=window_hours))
    if not agent_ids:
        return [], {
            "status": "needs_scope",
            "error": (
                f"No enrolled agent saw {block_ip} in the last {window_hours}h. "
                "Investigate the IP, pass agent_id for a specific host, or set "
                "fleet_wide=true with notes explaining why."
            ),
            "suggested_actions": [
                f"get_alerts_for_ip('{block_ip}')",
                "confirm_block_ip(..., agent_id='007')",
                "confirm_block_ip(..., fleet_wide=true, notes='...')",
            ],
        }

    hosts = [h for h in _active_hosts() if str(h.get("agent_id")) in agent_ids]
    if not hosts:
        return [], {
            "status": "needs_scope",
            "error": (
                f"Events reference agent_id(s) {sorted(agent_ids)} but no matching "
                "active host rows exist in hosts table."
            ),
            "agent_ids_from_events": sorted(agent_ids),
        }
    return hosts, None


def confirm_block_ip(
    block_id: str,
    notes: str = "",
    *,
    caller: str = "human",
    agent_id: str = "",
    fleet_wide: bool = False,
    window_hours: int = 48,
) -> dict[str, Any]:
    if caller != "human" and not allow_agent_block():
        return {
            "status": "denied",
            "error": (
                "confirm_block_ip requires human approval. "
                "Set LUREGUARD_ALLOW_AGENT_BLOCK=true only for testing."
            ),
        }

    if fleet_wide and not (notes or "").strip():
        return {
            "status": "error",
            "error": "fleet_wide=true requires non-empty notes explaining why all hosts are blocked",
        }

    entry = get_blocklist_entry_db(block_id)
    if not entry:
        return {"status": "error", "error": f"block_id {block_id} not found"}
    if entry.get("executed"):
        return {"status": "already_executed", "block_id": block_id, "ip": entry.get("ip")}

    password = onboard_ssh_password()
    if not password:
        return {
            "status": "error",
            "error": "ONBOARD_SSH_PASSWORD not set — cannot SSH to hosts for iptables",
        }

    try:
        block_ip = validate_ip(str(entry["ip"]), field="block_ip")
    except SSHValidationError as exc:
        return {"status": "error", "error": str(exc)}

    hosts, scope_error = _resolve_block_hosts(
        block_ip,
        agent_id=agent_id,
        fleet_wide=fleet_wide,
        window_hours=window_hours,
    )
    if scope_error:
        return scope_error

    results = []
    for host in hosts:
        host_ip = str(host["ip"])
        results.append(_ssh_iptables_drop(host_ip, block_ip, password))

    hosts_ok = sum(1 for r in results if r.get("ok"))
    scope_note = "fleet-wide" if fleet_wide else f"evidence-scoped ({len(hosts)} host(s))"

    if hosts_ok == 0:
        return {
            "status": "failed",
            "block_id": block_id,
            "ip": block_ip,
            "scope": scope_note,
            "agent_ids": sorted({str(h.get("agent_id")) for h in hosts if h.get("agent_id")}),
            "hosts_attempted": len(results),
            "hosts_ok": 0,
            "host_results": results,
            "error": "iptables DROP failed on all hosts — block remains pending for retry",
        }

    confirmed = confirm_blocklist_db(
        block_id,
        notes=notes or f"iptables {scope_note} on {hosts_ok}/{len(results)} host(s)",
    )
    status = "executed" if hosts_ok == len(results) else "partial"
    return {
        "status": status,
        "block_id": block_id,
        "ip": block_ip,
        "scope": scope_note,
        "agent_ids": sorted({str(h.get("agent_id")) for h in hosts if h.get("agent_id")}),
        "hosts_attempted": len(results),
        "hosts_ok": hosts_ok,
        "host_results": results,
        "blocklist": confirmed,
    }


def list_blocklist(pending_only: bool = False) -> str:
    rows = list_blocklist_db(pending_only=pending_only)
    return json.dumps({"count": len(rows), "entries": rows}, indent=2)
