"""
APScheduler tick loop — runs every 2 seconds.
Responsibilities:
  1. Refresh whitelist from DB
"""
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from loguru import logger

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


async def _run_retention() -> None:
    from retention import run_retention

    await run_retention()


async def _tick() -> None:
    """Main tick — called every 2 seconds."""
    await _refresh_whitelist_cache()


def start_scheduler() -> None:
    scheduler.add_job(_tick, "interval", seconds=2, id="main_tick")
    scheduler.add_job(_sync_hosts, "interval", seconds=60, id="hosts_sync")
    scheduler.add_job(_backfill_ip_geo, "interval", seconds=60, id="ip_geo_backfill")
    scheduler.add_job(_run_retention, "interval", days=1, id="retention", next_run_time=datetime.now())
    scheduler.start()
    logger.info("✅ APScheduler started")
