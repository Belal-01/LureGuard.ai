"""
LureGuard Core — FastAPI Application Factory
Entry point: uvicorn main:app
"""
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dotenv import load_dotenv

load_dotenv(_REPO_ROOT / ".env")

from contextlib import asynccontextmanager

from fastapi import FastAPI
from loguru import logger

from api.wazuh_endpoint import router as wazuh_router
from api.admin_api import router as admin_router
from api.metrics_endpoint import router as metrics_router
from db.session import AsyncSessionLocal, init_db
from modules.inference import load_model
from scheduler.tick_loop import start_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("LureGuard Core starting up...")

    # 1. Init DB (run Alembic migrations)
    await init_db()
    logger.info("✅ Database ready")

    from runtime.whitelist import refresh_whitelist_from_db, seed_whitelist_from_file_if_empty

    async with AsyncSessionLocal() as db:
        seeded = await seed_whitelist_from_file_if_empty(db)
        if seeded:
            await db.commit()
        n = await refresh_whitelist_from_db(db)
        await db.commit()
        logger.info(f"✅ Whitelist loaded from DB ({n} IP(s))")

    # 2. Load ML model + scaler (verifies SHA-256)
    load_model()
    logger.info("✅ ML model loaded")

    # 3. Start APScheduler tick loop
    start_scheduler()
    logger.info("✅ Scheduler started (tick=2s)")

    logger.info("🚀 LureGuard Core is READY")
    yield

    logger.info("LureGuard Core shutting down...")


app = FastAPI(
    title="LureGuard Core",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
)

# ── Routers ──────────────────────────────────────────────
app.include_router(wazuh_router)
app.include_router(admin_router)
app.include_router(metrics_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "lureguard-core"}
