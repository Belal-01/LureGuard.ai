"""Sync Wazuh agent fleet into Postgres hosts table."""

from __future__ import annotations

import os

import httpx
from loguru import logger

from db.session import AsyncSessionLocal
from db import crud


def _wazuh_config() -> tuple[str, str, str, bool]:
    base = os.getenv("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
    user = os.getenv("WAZUH_API_USER", "wazuh")
    password = os.getenv("WAZUH_API_PASSWORD", "LureGuard-Wazuh-Dev-2026!")
    verify = os.getenv("WAZUH_API_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
    return base, user, password, verify


async def sync_hosts_from_wazuh() -> int:
    """Pull agent list from Wazuh API and upsert into hosts table."""
    base, user, password, verify = _wazuh_config()
    updated = 0
    try:
        with httpx.Client(verify=verify, timeout=20.0) as client:
            auth = client.post(f"{base}/security/user/authenticate", auth=(user, password))
            auth.raise_for_status()
            token = auth.json().get("data", {}).get("token")
            if not token:
                return 0
            headers = {"Authorization": f"Bearer {token}"}
            resp = client.get(f"{base}/agents", headers=headers, params={"limit": 500})
            resp.raise_for_status()
            agents = resp.json().get("data", {}).get("affected_items", [])
    except Exception as exc:
        logger.debug("hosts sync skipped: {}", exc)
        return 0

    async with AsyncSessionLocal() as db:
        for agent in agents:
            agent_id = str(agent.get("id", ""))
            if not agent_id or agent_id == "000":
                continue
            name = agent.get("name") or f"agent-{agent_id}"
            ip = agent.get("ip") or agent.get("registerIP")
            status = agent.get("status", "unknown")
            os_name = agent.get("os", {}).get("name") if isinstance(agent.get("os"), dict) else None
            await crud.upsert_host(
                db,
                agent_id=agent_id,
                name=name,
                ip=ip,
                os_name=os_name,
                wazuh_status=status,
                enrolled_by="sync",
            )
            updated += 1
        await db.commit()
    if updated:
        logger.debug("Synced {} hosts from Wazuh", updated)
    return updated
