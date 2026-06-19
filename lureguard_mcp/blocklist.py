"""IP blocklist — recommend, confirm (human-approved), execute via iptables."""

from __future__ import annotations

import json
import logging
from typing import Any

from lureguard_mcp.config import allow_agent_block, onboard_ssh_password
from lureguard_mcp.db import (
    add_blocklist_db,
    confirm_blocklist_db,
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


def confirm_block_ip(block_id: str, notes: str = "", *, caller: str = "human") -> dict[str, Any]:
    if caller != "human" and not allow_agent_block():
        return {
            "status": "denied",
            "error": (
                "confirm_block_ip requires human approval. "
                "Set LUREGUARD_ALLOW_AGENT_BLOCK=true only for testing."
            ),
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

    hosts = [h for h in list_hosts_db() if h.get("wazuh_status") == "active" and h.get("ip")]
    results = []
    for host in hosts:
        host_ip = str(host["ip"])
        results.append(_ssh_iptables_drop(host_ip, block_ip, password))

    confirmed = confirm_blocklist_db(block_id, notes=notes or f"iptables on {len(results)} host(s)")
    return {
        "status": "executed",
        "block_id": block_id,
        "ip": block_ip,
        "hosts_attempted": len(results),
        "hosts_ok": sum(1 for r in results if r.get("ok")),
        "host_results": results,
        "blocklist": confirmed,
    }


def list_blocklist(pending_only: bool = False) -> str:
    rows = list_blocklist_db(pending_only=pending_only)
    return json.dumps({"count": len(rows), "entries": rows}, indent=2)
