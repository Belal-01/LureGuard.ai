"""Shared Wazuh Manager API helpers (core + MCP)."""

from __future__ import annotations

import os
from typing import Any

import httpx


def wazuh_api_config() -> tuple[str, str, str, bool]:
    base = os.getenv("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
    user = os.getenv("WAZUH_API_USER", "wazuh")
    password = os.getenv("WAZUH_API_PASSWORD", "LureGuard-Wazuh-Dev-2026!")
    verify = os.getenv("WAZUH_API_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
    return base, user, password, verify


def list_agents_sync(*, limit: int = 500) -> list[dict[str, Any]]:
    base, user, password, verify = wazuh_api_config()
    with httpx.Client(verify=verify, timeout=20.0) as client:
        auth = client.post(f"{base}/security/user/authenticate", auth=(user, password))
        auth.raise_for_status()
        token = auth.json().get("data", {}).get("token")
        if not token:
            return []
        headers = {"Authorization": f"Bearer {token}"}
        resp = client.get(f"{base}/agents", headers=headers, params={"limit": limit})
        resp.raise_for_status()
        return resp.json().get("data", {}).get("affected_items", [])
