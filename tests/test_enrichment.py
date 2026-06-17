"""Unit tests for lureguard_mcp enrichment helpers."""

from __future__ import annotations

import json

import pytest

from lureguard_mcp.enrichment import (
    analyze_web_attack,
    check_domain_virustotal,
    check_url_virustotal,
    defang_indicator,
    refang_indicator,
)


def test_defang_url():
    assert defang_indicator("https://evil.com/path?q=1", "url") == "hxxps://evil[.]com/path?q=1"


def test_defang_ip():
    assert defang_indicator("203.0.113.17", "ip") == "203[.]0[.]113[.]17"


def test_refang_roundtrip():
    raw = "https://evil.com/admin"
    defanged = defang_indicator(raw, "url")
    assert refang_indicator(defanged) == raw


def test_analyze_web_attack_sqli():
    payload = "GET /login?id=1' OR '1'='1 HTTP/1.1"
    data = json.loads(analyze_web_attack(payload))
    assert data["classified"] is True
    assert data["primary_attack_type"] == "sqli"
    assert data["mitre_technique"] == "T1190"


def test_analyze_web_attack_scanner_ua():
    payload = json.dumps({"raw_ref": "sqlmap/1.6 scanning wp-admin"})
    data = json.loads(analyze_web_attack(payload))
    assert data["classified"] is True
    assert data["primary_attack_type"] in {"scanner_ua", "probe"}


def test_analyze_web_attack_no_match():
    data = json.loads(analyze_web_attack("normal GET /health HTTP/1.1"))
    assert data["classified"] is False


def test_vt_url_degrades_without_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    data = json.loads(check_url_virustotal("https://example.com"))
    assert data["configured"] is False


def test_vt_domain_degrades_without_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    data = json.loads(check_domain_virustotal("example.com"))
    assert data["configured"] is False
