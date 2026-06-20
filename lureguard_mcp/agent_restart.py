"""Wazuh agent restart — recommend then human-confirmed execute."""

from __future__ import annotations

from typing import Any

from lureguard_mcp.config import allow_agent_restart
from lureguard_mcp.wazuh_client import WazuhClient


def recommend_restart_agent(
    agent_id: str,
    reason: str,
    investigation_id: str = "",
) -> dict[str, Any]:
    return {
        "status": "pending",
        "agent_id": agent_id,
        "reason": reason,
        "investigation_id": investigation_id or None,
        "message": (
            "Restart recommended — call confirm_restart_agent after human approval in chat."
        ),
    }


def confirm_restart_agent(
    agent_id: str,
    notes: str = "",
    *,
    caller: str = "human",
) -> dict[str, Any]:
    if caller != "human" and not allow_agent_restart():
        return {
            "status": "denied",
            "error": (
                "confirm_restart_agent requires human approval. "
                "Set LUREGUARD_ALLOW_AGENT_RESTART=true only for testing."
            ),
        }
    if not (agent_id or "").strip():
        return {"status": "error", "error": "agent_id is required"}
    result = WazuhClient().restart_agent(agent_id.strip())
    return {
        "status": "executed",
        "agent_id": agent_id.strip(),
        "notes": notes or "human-confirmed restart",
        "wazuh": result,
    }
