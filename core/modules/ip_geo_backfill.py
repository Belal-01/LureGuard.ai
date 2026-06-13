"""Backfill ip_geolocation rows for event source IPs missing geo data."""

from __future__ import annotations

from sqlalchemy import text

from db.crud import ensure_ip_geolocation
from db.session import AsyncSessionLocal


async def backfill_missing_ip_geolocations(*, limit: int = 20) -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                """
                SELECT DISTINCT host(e.src_ip) AS ip
                FROM events e
                WHERE e.src_ip IS NOT NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM ip_geolocation g WHERE g.ip = e.src_ip
                  )
                LIMIT :limit
                """
            ),
            {"limit": limit},
        )
        ips = [row.ip for row in result.all()]
        for ip in ips:
            await ensure_ip_geolocation(db, ip)
        if ips:
            await db.commit()
