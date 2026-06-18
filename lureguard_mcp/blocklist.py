"""IP blocklist — recommend, confirm (human-approved), execute via iptables."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

from lureguard_mcp.config import onboard_ssh_password
from lureguard_mcp.db import (
    confirm_blocklist_db,
    get_blocklist_entry_db,
    list_blocklist_db,
    list_hosts_db,
    add_blocklist_db,
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
    cmd = (
        f"sshpass -p {password!r} ssh -o StrictHostKeyChecking=no -T "
        f"ubuntu@{host_ip} "
        f"\"echo {password!r} | sudo -S iptables -C INPUT -s {block_ip} -j DROP 2>/dev/null "
        f"|| echo {password!r} | sudo -S iptables -I INPUT -s {block_ip} -j DROP\""
    )
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return {
            "host": host_ip,
            "ok": proc.returncode == 0,
            "stdout": (proc.stdout or "")[:500],
            "stderr": (proc.stderr or "")[:500],
        }
    except Exception as exc:
        return {"host": host_ip, "ok": False, "error": str(exc)}


def confirm_block_ip(block_id: str, notes: str = "") -> dict[str, Any]:
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

    block_ip = str(entry["ip"])
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
