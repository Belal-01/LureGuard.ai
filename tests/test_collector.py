"""Unit tests for collector.normalize_event()."""
from schemas.wazuh_alert import WazuhAlert
from modules.collector import normalize_event


def _make_alert(
    groups: list[str],
    *,
    srcip: str = "1.2.3.4",
    srcuser: str = "root",
    status: str = "invalid",
    rule_id: int = 5710,
    full_log: str = "sshd: Failed password",
) -> WazuhAlert:
    return WazuhAlert.model_validate(
        {
            "timestamp": "2026-05-20T14:31:02Z",
            "rule": {
                "id": rule_id,
                "level": 10,
                "groups": groups,
                "description": "sshd: authentication failed",
            },
            "agent": {"name": "target-host", "id": "001", "ip": "192.168.1.103"},
            "data": {"srcip": srcip, "srcuser": srcuser, "status": status},
            "location": "/var/log/auth.log",
            "full_log": full_log,
        }
    )


def test_auth_failed_channel():
    event = normalize_event(_make_alert(["authentication_failed", "sshd"]))
    assert event.channel == "sshd"
    assert event.event_type == "auth_failed"
    assert event.success is False
    assert event.wazuh_rule_id == 5710
    assert event.agent_name == "target-host"
    assert event.wazuh_rule_description == "sshd: authentication failed"
    assert event.location == "/var/log/auth.log"
    assert event.raw_ref


def test_auth_success():
    event = normalize_event(_make_alert(["authentication_success"], status="valid"))
    assert event.event_type == "auth_success"
    assert event.success is True


def test_src_ip_preserved():
    event = normalize_event(_make_alert(["sshd"], srcip="203.0.113.17"))
    assert event.src_ip == "203.0.113.17"


def test_fim_channel():
    alert = _make_alert(
        ["syscheck"],
        full_log="syscheck: Integrity checksum changed",
        rule_id=550,
    )
    alert = WazuhAlert.model_validate(
        {
            **alert.model_dump(),
            "syscheck": {"path": "/root/.ssh/authorized_keys", "event": "modified"},
        }
    )
    event = normalize_event(alert)
    assert event.channel == "syscheck"
    assert event.event_type == "fim_change"
    assert event.syscheck_path == "/root/.ssh/authorized_keys"


def test_rule_id_fallback_auth_failed():
    event = normalize_event(
        _make_alert(["sshd"], rule_id=5710, full_log="authentication failure")
    )
    assert event.event_type == "auth_failed"


def test_full_log_success_detection():
    event = normalize_event(
        _make_alert(
            ["sshd"],
            rule_id=5715,
            full_log="Accepted publickey for deploy from 10.0.0.5",
        )
    )
    assert event.event_type == "auth_success"
