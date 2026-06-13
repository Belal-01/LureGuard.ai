"""Threat intelligence enrichment."""

from __future__ import annotations

import json

import httpx

from lureguard_mcp.config import abuseipdb_api_key, virustotal_api_key


def check_ip_reputation(ip: str) -> str:
    key = abuseipdb_api_key()
    if not key:
        return json.dumps({"configured": False, "message": "ABUSEIPDB_API_KEY not set"})
    with httpx.Client(timeout=15.0) as client:
        resp = client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return json.dumps(
            {
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "is_whitelisted": data.get("isWhitelisted"),
            },
            indent=2,
        )


def check_ip_virustotal(ip: str) -> str:
    key = virustotal_api_key()
    if not key:
        return json.dumps({"configured": False, "message": "VIRUSTOTAL_API_KEY not set"})
    with httpx.Client(timeout=15.0) as client:
        resp = client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return json.dumps(
            {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
            },
            indent=2,
        )


def check_hash_virustotal(file_hash: str) -> str:
    key = virustotal_api_key()
    if not key:
        return json.dumps({"configured": False, "message": "VIRUSTOTAL_API_KEY not set"})
    with httpx.Client(timeout=15.0) as client:
        resp = client.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": key},
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return json.dumps(
            {
                "hash": file_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "meaningful_name": attrs.get("meaningful_name"),
            },
            indent=2,
        )
