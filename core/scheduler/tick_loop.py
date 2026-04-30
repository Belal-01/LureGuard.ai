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


async def _tick() -> None:
    """Main tick — called every 2 seconds."""
    cleanup_expired()
    dnat_active.set(get_active_count())


def start_scheduler() -> None:
    scheduler.add_job(_tick, "interval", seconds=2, id="main_tick")
    scheduler.start()
    logger.info("✅ APScheduler started")
