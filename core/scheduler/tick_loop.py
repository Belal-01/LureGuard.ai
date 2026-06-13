"""
APScheduler tick loop — runs every 2 seconds.
Responsibilities:
  1. Clean up expired DNAT rules (TTL)
  2. Refresh whitelist from DB
  3. Emit Prometheus gauge for active DNAT rules
"""
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from loguru import logger

from modules.enforcer import cleanup_expired, get_active_count
from api.metrics_endpoint import dnat_active

scheduler = AsyncIOScheduler()


async def _refresh_whitelist_cache() -> None:
    from db.session import AsyncSessionLocal
    from runtime.whitelist import refresh_whitelist_from_db

    async with AsyncSessionLocal() as db:
        await refresh_whitelist_from_db(db)
        await db.commit()


async def _sync_hosts() -> None:
    from modules.hosts_sync import sync_hosts_from_wazuh

    await sync_hosts_from_wazuh()


async def _backfill_ip_geo() -> None:
    from modules.ip_geo_backfill import backfill_missing_ip_geolocations

    await backfill_missing_ip_geolocations(limit=20)


async def _tick() -> None:
    """Main tick — called every 2 seconds."""
    cleanup_expired()
    await _refresh_whitelist_cache()
    dnat_active.set(get_active_count())


def start_scheduler() -> None:
    scheduler.add_job(_tick, "interval", seconds=2, id="main_tick")
    scheduler.add_job(_sync_hosts, "interval", seconds=60, id="hosts_sync")
    scheduler.add_job(_backfill_ip_geo, "interval", seconds=60, id="ip_geo_backfill")
    scheduler.start()
    logger.info("✅ APScheduler started")
