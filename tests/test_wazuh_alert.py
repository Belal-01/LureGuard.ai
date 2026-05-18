"""Tests for tolerant Wazuh alert schema."""
from schemas.wazuh_alert import WazuhAlert


def test_extra_fields_ignored():
    alert = WazuhAlert.model_validate(
        {
            "timestamp": "2026-05-20T14:31:02Z",
            "rule": {"id": "5710", "groups": ["sshd"]},
            "unknown_field": "ignored",
        }
    )
    assert alert.rule_id == 5710
    assert alert.rule_groups == ["sshd"]


def test_missing_full_log_defaults_empty():
    alert = WazuhAlert.model_validate({"timestamp": "2026-05-20T14:31:02Z"})
    assert alert.full_log == ""


def test_null_data_becomes_empty_dict():
    alert = WazuhAlert.model_validate({"timestamp": "t", "data": None})
    assert alert.data == {}
