"""Retention job for the events table — STO-1.

events is RANGE-partitioned by month (STO-2, migration n4o5p6q7r8s9), which
is what makes retention `DROP TABLE events_2026_05` — a catalog op — instead
of a bulk DELETE.

Three parts, kept separate on purpose (constraint: selection logic must be
pure and testable without a database):
  - `partitions_to_drop` / `months_spanned` — pure, no I/O.
    `partitions_to_drop` returns which dated partitions are fully outside a
    retention window, never `events_default` (STO-8: it holds every row that
    missed a dated range; dropping it would silently discard them).
    `months_spanned` returns every `YYYY_MM` a [start, end] range touches.
  - `ensure_future_partitions` / `drop_expired_partitions` /
    `reclaim_default_rows` — the DB-touching execution, built on the pure
    functions above.

STO-8 (the DEFAULT-partition trap): Postgres refuses to create a dated
partition whose range overlaps rows already sitting in `events_default`.
`ensure_future_partitions` (this month + `months_ahead` more, run daily)
stops *new* rows from ever reaching DEFAULT — a covering partition always
exists before a row with that timestamp can be inserted. That alone leaves
rows stranded in `events_default` from before this job existed permanently
undroppable, which reopens STO-1 for exactly the oldest data. So
`run_retention` also runs `reclaim_default_rows` first: it detaches DEFAULT,
creates the dated partitions those stranded rows span (`months_spanned`
tells it which), moves the rows across, and reattaches DEFAULT as the empty
safety net. See `reclaim_default_rows` for how concurrent inserts are kept
safe during the detach window.
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


def months_spanned(start: datetime, end: datetime) -> list[str]:
    """Pure — every `YYYY_MM` month touched by `[start, end]`, inclusive.

    No I/O: this is the selection logic `reclaim_default_rows` needs, split
    out so which partitions to create is testable without a database.
    """
    months = []
    cur = start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last = end.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    while cur <= last:
        months.append(f"{cur.year:04d}_{cur.month:02d}")
        cur = _add_months(cur, 1)
    return months


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


async def reclaim_default_rows(db) -> list[str]:
    """Migrate rows stranded in `events_default` into dated partitions — STO-8.

    One-time-per-row backfill for rows that landed in DEFAULT before
    `ensure_future_partitions` started keeping it empty. No-op (one cheap
    SELECT, no lock) once DEFAULT has nothing in it, so it's safe to call on
    every `run_retention` tick rather than as a separate manual step.

    The detach/create/move/reattach dance runs as ONE transaction:
      1. DETACH PARTITION events_default
      2. CREATE the dated partitions `months_spanned` says the stranded rows need
      3. move the rows across with a single DELETE ... RETURNING / INSERT
      4. ATTACH PARTITION events_default DEFAULT

    Concurrent inserts: DETACH takes an ACCESS EXCLUSIVE lock on `events`,
    and Postgres holds DDL locks until COMMIT, not just for the statement —
    so keeping every step inside one transaction means a concurrent INSERT
    simply blocks behind the lock for the (sub-second, ~132-row) duration of
    this function, then proceeds normally once we commit and DEFAULT is back.
    It never sees a moment where `events` has no DEFAULT to fall back to, so
    there's no window where an out-of-range insert can fail. If any step
    here raises, nothing commits, so Postgres rolls the whole transaction
    back and DEFAULT re-attaches itself as if the dance never started — a
    failure here cannot leave DEFAULT detached.

    ponytail: single blocking transaction — fine for a few hundred rows. If
    the stranded set were ever huge, holding ACCESS EXCLUSIVE that long
    would stall ingest for real; the upgrade path is batching the move in
    smaller transactions between a single detach/reattach pair.
    """
    min_ts, max_ts = (
        await db.execute(text("SELECT min(ts), max(ts) FROM events_default"))
    ).one()
    if min_ts is None:
        return []

    months = months_spanned(min_ts, max_ts)
    logger.warning(
        f"retention: reclaiming events_default rows spanning {months} — "
        "detaching DEFAULT for the duration of this transaction"
    )

    await db.execute(text("ALTER TABLE events DETACH PARTITION events_default"))

    existing = set(await _existing_partition_names(db))
    for ym in months:
        name = f"events_{ym}"
        if name in existing:
            continue
        year, month = int(ym[:4]), int(ym[5:7])
        month_start = datetime(year, month, 1)
        month_end = _add_months(month_start, 1)
        await db.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF events "
                f"FOR VALUES FROM ('{month_start.date()}') TO ('{month_end.date()}')"
            )
        )

    await db.execute(
        text(
            "WITH moved AS (DELETE FROM events_default RETURNING *) "
            "INSERT INTO events SELECT * FROM moved"
        )
    )

    await db.execute(text("ALTER TABLE events ATTACH PARTITION events_default DEFAULT"))
    await db.commit()
    return months


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
        await reclaim_default_rows(db)

    async with AsyncSessionLocal() as db:
        await ensure_future_partitions(db)

    async with AsyncSessionLocal() as db:
        await drop_expired_partitions(db, retention_days=settings.retention_days)
