"""Sync Wazuh agent fleet into Postgres hosts table."""

from __future__ import annotations

from loguru import logger

from connectors.wazuh_api import list_agents_sync
from db.session import AsyncSessionLocal
from db import crud


async def sync_hosts_from_wazuh() -> int:
    """Pull agent list from Wazuh API and upsert into hosts table."""
    updated = 0
    try:
        agents = list_agents_sync()
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
