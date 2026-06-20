"""
In-memory whitelist cache — source of truth is Postgres `whitelist` table.

Refreshed on startup, every scheduler tick, and after admin API changes.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from pathlib import Path

from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from runtime.paths import whitelist_path

_ips: set[str] = set()


def _normalize_ip(ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return None


def refresh_cache(ips: list[str]) -> None:
    global _ips
    normalized = {_normalize_ip(ip) for ip in ips if ip and ip.strip()}
    _ips = {ip for ip in normalized if ip is not None}


def reset_whitelist_cache() -> None:
    refresh_cache([])


def is_whitelisted(
    src_ip: str | None,
    src_user: str | None = None,
    event_ts: datetime | None = None,
) -> bool:
    """True when client IP is in the DB-backed cache (user/expiry not in schema yet)."""
    del src_user, event_ts
    normalized = _normalize_ip(src_ip) if src_ip else None
    return normalized is not None and normalized in _ips


async def refresh_whitelist_from_db(db: AsyncSession) -> int:
    from db import crud

    ips = await crud.get_whitelist(db)
    refresh_cache(ips)
    return len(ips)


async def seed_whitelist_from_file_if_empty(db: AsyncSession) -> int:
    """One-time bootstrap: import config/whitelist.json when the table has no rows."""
    from db.models import Whitelist

    count = await db.scalar(select(func.count()).select_from(Whitelist))
    if count and count > 0:
        return 0

    path = whitelist_path()
    if not path.exists():
        return 0

    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(f"Could not read whitelist seed file {path}: {exc}")
        return 0

    from db import crud

    added = 0
    for entry in payload.get("entries", []):
        raw_ip = entry.get("ip")
        if not raw_ip:
            continue
        try:
            ipaddress.ip_address(str(raw_ip).strip())
        except ValueError:
            continue
        note = entry.get("note") or entry.get("reason")
        await crud.add_whitelist_ip(
            db,
            str(raw_ip).strip(),
            reason=str(note) if note else "imported from whitelist.json",
            added_by="seed",
        )
        added += 1

    if added:
        logger.info(f"Seeded {added} whitelist IP(s) from {path}")
    return added
