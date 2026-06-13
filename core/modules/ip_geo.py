"""Best-effort public IP geolocation for Grafana geomap (ip-api.com, no API key)."""

from __future__ import annotations

import ipaddress

import httpx
from loguru import logger

_LOOKUP_FIELDS = "status,country,countryCode,lat,lon,query"


def is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(str(ip).split("/")[0]).is_global
    except ValueError:
        return False


async def lookup_ip(ip: str) -> dict[str, str | float] | None:
    if not is_public_ip(ip):
        return None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}?fields={_LOOKUP_FIELDS}",
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.debug(f"IP geo lookup failed for {ip}: {exc}")
        return None

    if data.get("status") != "success":
        return None

    lat = data.get("lat")
    lon = data.get("lon")
    if lat is None or lon is None:
        return None

    return {
        "country_code": str(data.get("countryCode") or ""),
        "country_name": str(data.get("country") or ""),
        "lat": float(lat),
        "lon": float(lon),
    }
