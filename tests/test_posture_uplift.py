"""Tests for posture uplift — EOL OS, EPSS triage, user risk scoring."""

from __future__ import annotations

from lureguard_mcp.cve_triage import EPSS_URL, fetch_epss_batch, is_eol_os, normalize_cve_id, triage_finding
from lureguard_mcp.user_scanner import _normalize_wazuh_user, _score_user


def test_is_eol_os_ubuntu_18_04():
    assert is_eol_os("ubuntu", "18.04", "Ubuntu") is True


def test_is_eol_os_ubuntu_22_04_not_eol():
    assert is_eol_os("ubuntu", "22.04", "Ubuntu") is False


def test_triage_eol_boosts_critical_priority():
    result = triage_finding(
        vuln={},
        package_name="openssl",
        package_version="1.0.0",
        ecosystem="Ubuntu",
        cve_id="CVE-2020-0001",
        severity="critical",
        cvss=9.0,
        running_processes={"openssl"},
        eol_os=True,
    )
    assert result is not None
    assert result["priority_score"] >= 50


def test_score_user_uid_zero_non_root_critical():
    assert _score_user("toor", 0, "/bin/bash", "2026-01-01") == "critical"


def test_score_user_nologin_info():
    assert _score_user("daemon", 1, "/usr/sbin/nologin", None) == "info"


def test_epss_api_url_not_deprecated_v1_0():
    assert EPSS_URL == "https://api.first.org/data/v1/epss"


def test_normalize_cve_id_ubuntu_prefix():
    assert normalize_cve_id("UBUNTU-CVE-2021-44228") == "CVE-2021-44228"


def test_fetch_epss_batch_ubuntu_prefixed_ids():
    scores = fetch_epss_batch(["UBUNTU-CVE-2021-44228"])
    assert "CVE-2021-44228" in scores


def test_normalize_wazuh_user_nested_payload():
    row = {
        "user": {
            "name": "ubuntu",
            "id": 1000,
            "group_id": 1000,
            "shell": "/bin/bash",
        },
        "login": {"status": 0},
    }
    out = _normalize_wazuh_user(row)
    assert out is not None
    assert out["username"] == "ubuntu"
    assert out["uid"] == 1000
    assert out["gid"] == 1000
