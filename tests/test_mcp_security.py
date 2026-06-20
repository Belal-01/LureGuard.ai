"""Security and containment tests for lureguard_mcp."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from lureguard_mcp import correlator
from lureguard_mcp.blocklist import confirm_block_ip, recommend_block_ip
from lureguard_mcp.whitelist import remove_whitelist_ip


def test_container_posture_mcp_calls_impl_not_self(monkeypatch: pytest.MonkeyPatch):
    called = {}

    def fake_impl(agent_id: str, image_ref: str = "", limit: int = 200):
        called["agent_id"] = agent_id
        called["image_ref"] = image_ref
        called["limit"] = limit
        return {"agent_id": agent_id, "containers": []}

    monkeypatch.setattr("lureguard_mcp.server._container_posture_impl", fake_impl)

    from lureguard_mcp.server import get_agent_container_posture

    raw = get_agent_container_posture("007", image_ref="nginx:latest", limit=10)
    import json

    data = json.loads(raw)
    assert called == {"agent_id": "007", "image_ref": "nginx:latest", "limit": 10}
    assert data["agent_id"] == "007"


def test_confirm_block_mcp_uses_human_caller(monkeypatch: pytest.MonkeyPatch):
    captured = {}

    def fake_confirm(*args, **kwargs):
        captured.update(kwargs)
        return {"status": "executed"}

    monkeypatch.setattr("lureguard_mcp.server.blocklist_confirm", fake_confirm)

    from lureguard_mcp.server import confirm_block_ip

    confirm_block_ip("block-123", notes="user approved")
    assert captured.get("caller", "human") != "agent"


def test_remove_whitelist_denied_for_agent_caller(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LUREGUARD_ALLOW_AGENT_WHITELIST", "false")
    result = remove_whitelist_ip(ip="203.0.113.1", caller="agent")
    assert result["status"] == "denied"


def test_recommend_block_rejects_invalid_ip():
    result = recommend_block_ip("not-an-ip", reason="test")
    assert result["status"] == "error"
    assert "invalid" in result["error"]


def test_confirm_block_needs_scope_when_no_events(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ONBOARD_SSH_PASSWORD", "test-pass")
    monkeypatch.setattr(
        "lureguard_mcp.blocklist.get_blocklist_entry_db",
        lambda block_id: {
            "block_id": block_id,
            "ip": "203.0.113.50",
            "executed": False,
        },
    )
    monkeypatch.setattr("lureguard_mcp.blocklist.get_agent_ids_for_src_ip_db", lambda *a, **k: [])
    result = confirm_block_ip("b1", notes="test")
    assert result["status"] == "needs_scope"


def test_confirm_block_scoped_to_event_agents(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ONBOARD_SSH_PASSWORD", "test-pass")
    monkeypatch.setattr(
        "lureguard_mcp.blocklist.get_blocklist_entry_db",
        lambda block_id: {
            "block_id": block_id,
            "ip": "203.0.113.50",
            "executed": False,
        },
    )
    monkeypatch.setattr(
        "lureguard_mcp.blocklist.get_agent_ids_for_src_ip_db",
        lambda *a, **k: ["007"],
    )
    monkeypatch.setattr(
        "lureguard_mcp.blocklist.list_hosts_db",
        lambda: [
            {
                "agent_id": "007",
                "ip": "192.168.28.131",
                "wazuh_status": "active",
            },
            {
                "agent_id": "008",
                "ip": "192.168.28.134",
                "wazuh_status": "active",
            },
        ],
    )
    ssh_calls: list[str] = []

    def fake_ssh(host_ip: str, block_ip: str, password: str):
        ssh_calls.append(host_ip)
        return {"host": host_ip, "ok": True}

    monkeypatch.setattr("lureguard_mcp.blocklist._ssh_iptables_drop", fake_ssh)
    monkeypatch.setattr(
        "lureguard_mcp.blocklist.confirm_blocklist_db",
        lambda block_id, notes=None: {"block_id": block_id},
    )

    result = confirm_block_ip("b1", notes="scoped block")
    assert result["status"] == "executed"
    assert ssh_calls == ["192.168.28.131"]


def test_correlator_filters_by_datetime(monkeypatch: pytest.MonkeyPatch):
    old_event = {"src_ip": "203.0.113.1", "ts": "2020-01-01T00:00:00", "wazuh_rule_level": 10}
    new_event = {"src_ip": "203.0.113.2", "ts": "2099-06-01T12:00:00", "wazuh_rule_level": 10}
    monkeypatch.setattr(
        "lureguard_mcp.correlator.search_events",
        lambda **kwargs: [old_event, new_event],
    )
    out = correlator.correlate_alerts(window_hours=24, min_level=3)
    ips = {c["src_ip"] for c in out["clusters"]}
    assert "203.0.113.1" not in ips
    assert "203.0.113.2" in ips


def test_apply_system_update_denied_for_agent_caller(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LUREGUARD_ALLOW_AGENT_SYSTEM_UPDATE", "false")
    from lureguard_mcp.system_update import apply_system_update

    result = apply_system_update(caller="agent")
    assert result["status"] == "denied"


def test_redact_tool_args_redacts_ssh_password():
    from lureguard_mcp.secrets import redact_tool_args

    def sample_tool(ip: str, ssh_password: str = "") -> str:
        return ip

    redacted = redact_tool_args(sample_tool, ("10.0.0.1", "secret123"), {})
    assert redacted["ssh_password"] == "***REDACTED***"
