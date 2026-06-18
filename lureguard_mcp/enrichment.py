"""Threat intelligence enrichment and web-attack classification."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import quote

import httpx

from lureguard_mcp.config import abuseipdb_api_key, urlhaus_api_url, virustotal_api_key


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return True
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False


def _lookup_geo_db(ip: str) -> dict[str, Any]:
    from lureguard_mcp.db import get_conn

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


def _abuseipdb_dict(ip: str) -> dict[str, Any]:
    key = abuseipdb_api_key()
    if not key:
        return {"configured": False}
    try:
        with httpx.Client(timeout=12.0) as client:
            resp = client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "configured": True,
                "score": data.get("abuseConfidenceScore"),
                "reports": data.get("totalReports"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "is_whitelisted": data.get("isWhitelisted"),
            }
    except Exception as exc:
        return {"configured": True, "error": str(exc)}


def _virustotal_ip_dict(ip: str) -> dict[str, Any]:
    key = virustotal_api_key()
    if not key:
        return {"configured": False}
    try:
        with httpx.Client(timeout=12.0) as client:
            resp = client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": key},
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "configured": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
            }
    except Exception as exc:
        return {"configured": True, "error": str(exc)}


def _derive_verdict(abuse: dict[str, Any], vt: dict[str, Any]) -> tuple[str, str]:
    abuse_score = abuse.get("score") or 0
    vt_mal = vt.get("malicious") or 0
    vt_susp = vt.get("suspicious") or 0
    if abuse_score >= 75 or vt_mal >= 5:
        return "malicious", "high"
    if abuse_score >= 25 or vt_mal >= 1 or vt_susp >= 2:
        return "suspicious", "medium"
    if abuse.get("is_whitelisted"):
        return "benign", "high"
    if not abuse.get("configured") and not vt.get("configured"):
        return "undetermined", "low"
    return "benign", "medium"


def get_ip_context(ip: str) -> str:
    """Compound enrichment: geo + AbuseIPDB + VirusTotal in one call."""
    clean = refang_indicator(ip).strip()
    if _is_private_ip(clean):
        return json.dumps(
            {
                "ip": clean,
                "private": True,
                "geo": {},
                "abuse": {"skipped": "private IP"},
                "virustotal": {"skipped": "private IP"},
                "verdict": "internal",
                "verdict_confidence": "high",
            },
            indent=2,
        )
    geo = _lookup_geo_db(clean)
    abuse = _abuseipdb_dict(clean)
    vt = _virustotal_ip_dict(clean)
    verdict, confidence = _derive_verdict(abuse, vt)
    return json.dumps(
        {
            "ip": clean,
            "geo": geo,
            "abuse": abuse,
            "virustotal": vt,
            "verdict": verdict,
            "verdict_confidence": confidence,
        },
        indent=2,
    )


def check_tls(host: str, port: int = 443) -> str:
    """Check TLS certificate and cipher for a host:port."""
    import socket
    import ssl
    from datetime import datetime, timezone

    result: dict[str, Any] = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result["cipher"] = cipher[0] if cipher else None
                result["protocol"] = cipher[1] if cipher else None
                if cert:
                    result["subject"] = dict(x[0] for x in cert.get("subject", ()))
                    not_after = cert.get("notAfter")
                    result["not_after"] = not_after
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                        result["days_until_expiry"] = days_left
                        result["expired"] = days_left < 0
    except Exception as exc:
        result["error"] = str(exc)
    return json.dumps(result, indent=2)


def defang_indicator(value: str, ioc_type: str | None = None) -> str:
    """Defang an IOC for safe sharing in reports."""
    text = value.strip()
    kind = (ioc_type or "").lower()
    if kind in {"url", "domain"} or "://" in text or text.startswith("www."):
        text = re.sub(r"(?i)^https?://", lambda m: m.group(0).replace("ttp", "xxp"), text)
        return text.replace(".", "[.]")
    if kind == "email" or "@" in text:
        return text.replace("@", "[at]")
    if kind == "ip":
        return text.replace(".", "[.]")
    return text.replace(".", "[.]")


def refang_indicator(value: str) -> str:
    """Refang a defanged IOC for API lookups."""
    text = value.strip()
    text = re.sub(r"(?i)^hxxps?\[:\]//", lambda m: m.group(0).replace("xxp", "ttp").replace("[:]", ":"), text)
    text = re.sub(r"(?i)^hxxps?://", lambda m: m.group(0).replace("xxp", "ttp"), text)
    text = text.replace("[.]", ".")
    text = text.replace("[:]", ":")
    text = text.replace("[at]", "@")
    return text


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


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


def check_url_virustotal(url: str) -> str:
    key = virustotal_api_key()
    if not key:
        return json.dumps({"configured": False, "message": "VIRUSTOTAL_API_KEY not set"})
    clean = refang_indicator(url)
    with httpx.Client(timeout=15.0) as client:
        resp = client.get(
            f"https://www.virustotal.com/api/v3/urls/{_vt_url_id(clean)}",
            headers={"x-apikey": key},
        )
        if resp.status_code == 404:
            submit = client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": key},
                data={"url": clean},
            )
            submit.raise_for_status()
            return json.dumps(
                {
                    "url": clean,
                    "status": "submitted",
                    "message": "URL submitted to VirusTotal; re-check in ~1 minute",
                },
                indent=2,
            )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return json.dumps(
            {
                "url": clean,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "categories": attrs.get("categories", {}),
            },
            indent=2,
        )


def check_domain_virustotal(domain: str) -> str:
    key = virustotal_api_key()
    if not key:
        return json.dumps({"configured": False, "message": "VIRUSTOTAL_API_KEY not set"})
    clean = refang_indicator(domain).lower()
    with httpx.Client(timeout=15.0) as client:
        resp = client.get(
            f"https://www.virustotal.com/api/v3/domains/{quote(clean, safe='')}",
            headers={"x-apikey": key},
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return json.dumps(
            {
                "domain": clean,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "categories": attrs.get("categories", {}),
                "registrar": attrs.get("registrar"),
            },
            indent=2,
        )


def check_url_urlhaus(url: str) -> str:
    clean = refang_indicator(url)
    api_url = urlhaus_api_url()
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(
            api_url,
            data={"url": clean},
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        return json.dumps(
            {
                "url": clean,
                "query_status": data.get("query_status"),
                "threat": data.get("threat"),
                "url_status": data.get("url_status"),
                "tags": data.get("tags", []),
                "blacklists": data.get("blacklists", {}),
            },
            indent=2,
        )


_WEB_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'1'='1)", "sqli", "T1190", "Initial Access"),
    (r"(?i)(<script|javascript:|onerror=|onload=)", "xss", "T1189", "Initial Access"),
    (r"(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self)", "lfi", "T1190", "Initial Access"),
    (r"(?i)(cmd=|exec\(|system\(|/bin/sh|wget\s+http)", "rce", "T1190", "Initial Access"),
    (r"(?i)(sqlmap|nikto|nmap|masscan|gobuster|dirbuster)", "scanner_ua", "T1595", "Reconnaissance"),
    (r"(?i)(wp-admin|phpmyadmin|\.env|/admin/config)", "probe", "T1190", "Initial Access"),
]


def analyze_web_attack(event_payload: str) -> str:
    """Classify likely web attack patterns from event text or JSON payload."""
    text = event_payload.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            parts = [
                str(parsed.get(k, ""))
                for k in ("raw_ref", "event_type", "username", "syscheck_path", "channel")
            ]
            text = " ".join(parts) + " " + text
    except json.JSONDecodeError:
        pass

    matches: list[dict[str, Any]] = []
    for pattern, attack_type, technique, tactic in _WEB_PATTERNS:
        if re.search(pattern, text):
            matches.append(
                {
                    "attack_type": attack_type,
                    "mitre_technique": technique,
                    "mitre_tactic": tactic,
                    "pattern": pattern,
                }
            )

    if not matches:
        return json.dumps(
            {
                "classified": False,
                "message": "No known web attack signature matched",
                "input_preview": text[:500],
            },
            indent=2,
        )

    primary = matches[0]
    return json.dumps(
        {
            "classified": True,
            "primary_attack_type": primary["attack_type"],
            "mitre_technique": primary["mitre_technique"],
            "mitre_tactic": primary["mitre_tactic"],
            "matches": matches,
            "confidence": "high" if len(matches) > 1 else "medium",
        },
        indent=2,
    )
