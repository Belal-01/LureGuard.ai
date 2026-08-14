"""Retention job for the events table — STO-1.

events is RANGE-partitioned by month (STO-2, migration n4o5p6q7r8s9), which
is what makes retention `DROP TABLE events_2026_05` — a catalog op — instead
of a bulk DELETE.

Two halves, kept separate on purpose (constraint: selection logic must be
pure and testable without a database):
  - `partitions_to_drop` — pure, no I/O. Given partition names + a window,
    returns which dated partitions are fully outside it. Never returns
    `events_default` (STO-8: it holds every row that missed a dated range;
    dropping it would silently discard them).
  - `ensure_future_partitions` / `drop_expired_partitions` — the DB-touching
    execution, built on top of the pure function.

STO-8 (the DEFAULT-partition trap): Postgres refuses to create a dated
partition whose range overlaps rows already sitting in `events_default`.
The chosen fix is to always create partitions *ahead* of need (this month +
`months_ahead` more, run daily) so a covering partition exists before any
row with that timestamp is ever inserted — new rows never reach DEFAULT in
the first place. Rows already stranded in `events_default` from before this
job existed (STO-8's 132 historical rows) are left alone: migrating them
requires detaching DEFAULT and moving rows, which reintroduces the very
"violates partition constraint" failure this design avoids, and doing so
isn't required for retention to work going forward.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from loguru import logger
from sqlalchemy import text

_PARTITION_RE = re.compile(r"^events_(\d{4})_(\d{2})$")


def partitions_to_drop(names: list[str], retention_days: int, now: datetime) -> list[str]:
    """Pure selection — which dated partitions are fully older than the window.

    `names` is every partition of `events` (dated + `events_default`).
    Only `events_YYYY_MM`-shaped names are ever eligible; anything else
    (including `events_default`) is skipped.
    """
    cutoff = now - timedelta(days=retention_days)
    drop = []
    for name in names:
        m = _PARTITION_RE.match(name)
        if not m:
            continue
        year, month = int(m.group(1)), int(m.group(2))
        end = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)
        if end <= cutoff:
            drop.append(name)
    return sorted(drop)


def _add_months(dt: datetime, n: int) -> datetime:
    total = dt.month - 1 + n
    year = dt.year + total // 12
    month = total % 12 + 1
    return dt.replace(year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0)


async def _existing_partition_names(db) -> list[str]:
    result = await db.execute(
        text(
            """
            SELECT c.relname
            FROM pg_inherits i
            JOIN pg_class c ON c.oid = i.inhrelid
            JOIN pg_class p ON p.oid = i.inhparent
            WHERE p.relname = 'events'
            """
        )
    )
    return [row.relname for row in result.all()]


async def ensure_future_partitions(db, months_ahead: int = 2, now: datetime | None = None) -> list[str]:
    """Create dated partitions for the current month + `months_ahead` more.

    Idempotent — skips any month that already has a partition. Returns the
    names created.
    """
    now = now or datetime.utcnow()
    existing = set(await _existing_partition_names(db))
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    created = []
    for i in range(months_ahead + 1):
        month_start = _add_months(start, i)
        month_end = _add_months(start, i + 1)
        name = f"events_{month_start:%Y_%m}"
        if name in existing:
            continue
        logger.info(
            f"retention: creating partition {name} for [{month_start.date()}, {month_end.date()})"
        )
        # DDL — asyncpg's extended protocol rejects bind params in PARTITION OF
        # FOR VALUES, so bounds are inlined. Safe: they're computed dates, not
        # user input (same approach as migration n4o5p6q7r8s9's DO block).
        await db.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF events "
                f"FOR VALUES FROM ('{month_start.date()}') TO ('{month_end.date()}')"
            )
        )
        created.append(name)
    if created:
        await db.commit()
    return created


async def drop_expired_partitions(db, retention_days: int, now: datetime | None = None) -> list[str]:
    """Drop dated partitions fully outside the retention window.

    Logs the row count of each partition loudly before dropping it — this
    is destructive and irreversible.
    """
    now = now or datetime.utcnow()
    existing = await _existing_partition_names(db)
    to_drop = partitions_to_drop(existing, retention_days, now)
    dropped = []
    for name in to_drop:
        row_count = (await db.execute(text(f"SELECT count(*) FROM {name}"))).scalar_one()
        logger.warning(
            f"retention: DROPPING partition {name} ({row_count} rows) — older than "
            f"{retention_days}d retention window, cutoff={now - timedelta(days=retention_days)}. "
            "This is irreversible."
        )
        await db.execute(text(f"DROP TABLE {name}"))
        dropped.append(name)
    if dropped:
        await db.commit()
    return dropped


async def run_retention() -> None:
    """Scheduler entrypoint: top up future partitions, then drop expired ones."""
    from config import settings
    from db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        await ensure_future_partitions(db)

    async with AsyncSessionLocal() as db:
        await drop_expired_partitions(db, retention_days=settings.retention_days)
