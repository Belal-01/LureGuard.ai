"""
Async SQLAlchemy engine + session factory.
"""
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from loguru import logger

from db.models import Base

# Read DATABASE_URL from Docker Secret or fallback env
def _get_db_url() -> str:
    secret = Path("/run/secrets/db_password")
    if secret.exists():
        pw = secret.read_text().strip()
        return f"postgresql+asyncpg://lureguard:{pw}@postgres:5432/lureguard"
    # Fallback for local dev
    return "postgresql+asyncpg://lureguard:lureguard@localhost:5432/lureguard"


engine = create_async_engine(
    _get_db_url(),
    echo=False,
    pool_size=5,
    max_overflow=10,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """Create all tables (used in dev/test — Alembic handles production)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables verified/created")


async def get_db():
    """FastAPI dependency — yields an AsyncSession."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
