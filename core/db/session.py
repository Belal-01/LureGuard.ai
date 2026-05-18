"""
Async SQLAlchemy engine + session factory.
"""
import os
from pathlib import Path
from urllib.parse import quote_plus

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from loguru import logger

from db.models import Base

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_local_db_password() -> str | None:
    path = _REPO_ROOT / "secrets" / "db_password.txt"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return None


def _get_db_url() -> str:
    if url := os.getenv("DATABASE_URL", "").strip():
        return url

    docker_secret = Path("/run/secrets/db_password")
    if docker_secret.exists():
        pw = quote_plus(docker_secret.read_text(encoding="utf-8").strip())
        return f"postgresql+asyncpg://lureguard:{pw}@postgres:5432/lureguard"

    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5433")
    pw = quote_plus(_read_local_db_password() or os.getenv("POSTGRES_PASSWORD", "lureguard"))
    return f"postgresql+asyncpg://lureguard:{pw}@{host}:{port}/lureguard"


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
