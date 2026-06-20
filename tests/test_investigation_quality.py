"""Tests for Tier 1 investigation quality roadmap."""

from __future__ import annotations

import json

from core.modules.collector import normalize_event
from core.schemas.wazuh_alert import WazuhAlert
from lureguard_mcp.container_posture import _parse_trivy_json
from lureguard_mcp.presentation import infer_attack_phases
from lureguard_mcp.enrichment import _derive_verdict, get_ip_context


def test_infer_attack_phases_brute_force_and_honeypot():
    events = [
        {"channel": "sshd", "event_type": "auth_failed"},
        {"channel": "cowrie", "event_type": "cowrie_session"},
    ]
    phases = infer_attack_phases(events)
    assert "brute_force" in phases
    assert "honeypot_contact" in phases


def test_derive_verdict_malicious():
    abuse = {"score": 90, "configured": True}
    vt = {"malicious": 10, "configured": True}
    verdict, conf = _derive_verdict(abuse, vt)
    assert verdict == "malicious"
    assert conf == "high"


def test_get_ip_context_private_ip():
    out = json.loads(get_ip_context("192.168.1.50"))
    assert out["private"] is True
    assert out["verdict"] == "internal"


def test_parse_trivy_json_extracts_cves():
    payload = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1",
                        "FixedVersion": "1.1.2",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 7.5}},
                    }
                ]
            }
        ]
    }
    findings = _parse_trivy_json(payload)
    assert len(findings) == 1
    assert findings[0]["cve_id"] == "CVE-2024-1234"
    assert findings[0]["cvss"] == 7.5


def test_collector_maps_web_attack():
    alert = WazuhAlert.model_validate(
        {
            "timestamp": "2026-06-18T12:00:00.000+0000",
            "rule": {
                "id": 31103,
                "level": 10,
                "description": "SQL injection attempt",
                "groups": ["web", "attack", "sql_injection"],
            },
            "agent": {"id": "007", "name": "test-host"},
            "data": {"srcip": "203.0.113.1"},
            "full_log": "GET /?id=1' OR 1=1--",
        }
    )
    event = normalize_event(alert)
    assert event.channel == "web"
    assert event.event_type == "web_attack"
