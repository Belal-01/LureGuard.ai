"""Unit tests for collector.py — normalize_event()"""
import pytest
from schemas.wazuh_alert import WazuhAlert, WazuhRule, WazuhData, WazuhAgent
from modules.collector import normalize_event


def _make_alert(groups, srcip="1.2.3.4", srcuser="root", status="invalid"):
    return WazuhAlert(
        timestamp="2026-05-20T14:31:02Z",
        rule=WazuhRule(id=5710, level=10, groups=groups),
        agent=WazuhAgent(name="target-host"),
        data=WazuhData(srcip=srcip, srcuser=srcuser, status=status),
        full_log="sshd: Failed password",
    )


def test_auth_failed_channel():
    event = normalize_event(_make_alert(["authentication_failed", "sshd"]))
    assert event.channel == "sshd"
    assert event.event_type == "auth_failed"
    assert event.success is False


def test_auth_success():
    event = normalize_event(_make_alert(["authentication_success"], status="valid"))
    assert event.event_type == "auth_success"
    assert event.success is True


def test_src_ip_preserved():
    event = normalize_event(_make_alert(["sshd"], srcip="203.0.113.17"))
    assert event.src_ip == "203.0.113.17"


def test_fim_channel():
    from schemas.wazuh_alert import WazuhSyscheck
    alert = _make_alert(["syscheck"])
    alert.syscheck = WazuhSyscheck(path="/root/.ssh/authorized_keys", event="modified")
    event = normalize_event(alert)
    assert event.channel == "syscheck"
    assert event.event_type == "fim_change"
    assert event.syscheck_path == "/root/.ssh/authorized_keys"
