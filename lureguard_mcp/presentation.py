"""DTO shaping and presentation helpers for MCP query results."""

from __future__ import annotations

from typing import Any

from lureguard_mcp.untrusted_text import shape_event_row as _shape_event_row


def row_to_dict(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in row.items():
        if hasattr(val, "isoformat"):
            out[key] = val.isoformat()
        else:
            out[key] = str(val) if val is not None and key in ("src_ip", "ip") else val
    return out


def shape_event_row(row: dict[str, Any]) -> dict[str, Any]:
    return _shape_event_row(row_to_dict(row))


def infer_attack_phases(events: list[dict]) -> list[str]:
    phases: list[str] = []
    channels = {e.get("channel") for e in events}
    types = {e.get("event_type") for e in events}
    if "auth_failed" in types or channels & {"sshd"}:
        phases.append("brute_force")
    if channels & {"cowrie"} or "cowrie_session" in types:
        phases.append("honeypot_contact")
    if channels & {"syscheck"} or "fim_change" in types:
        phases.append("file_integrity")
    if channels & {"rootcheck"}:
        phases.append("rootkit_detection")
    if channels & {"web", "docker"} or types & {"web_attack", "web_scan"}:
        phases.append("web_attack")
    if "auth_success" in types:
        phases.append("initial_access_attempt")
    return phases
