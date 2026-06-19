"""Geo lookup from Postgres ip_geolocation cache."""

from __future__ import annotations

from typing import Any

from lureguard_mcp.repos.connection import get_conn


def lookup_geo_db(ip: str) -> dict[str, Any]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT country_code, country_name, lat, lon
                FROM ip_geolocation WHERE ip = %s::inet
                """,
                (ip,),
            )
            row = cur.fetchone()
    if not row:
        return {}
    return {
        "country": row[0],
        "city": row[1],
        "lat": row[2],
        "lon": row[3],
    }
