import uuid
from datetime import datetime

from modules.alert_dedup import reset as reset_dedup, should_send_telegram
from modules.alert_format import format_ssh_alert
from schemas.decision_result import DecisionResult
from schemas.normalized_event import NormalizedEvent


def test_format_ssh_alert_html():
    dec = DecisionResult(
        id=uuid.uuid4(),
        ts=datetime.utcnow(),
        decision="alert",
        p=0.407,
        score=0.407,
        t1=0.4,
        t2=0.7,
        model_version="1.0.0",
        features_hash="abc",
        reason="ignored",
    )
    event = NormalizedEvent(
        src_ip="1.2.3.4",
        channel="sshd",
        event_type="auth_failed",
        username="root",
        agent_name="target-vm",
        agent_id="002",
        wazuh_rule_id=5710,
        wazuh_rule_level=10,
        wazuh_rule_description="sshd: authentication failed",
        location="/var/log/auth.log",
        raw_ref="Failed password for root from 1.2.3.4 port 22 ssh2",
    )
    text = format_ssh_alert(dec, event, t1=0.4, t2=0.7)
    assert "🟠 HIGH" in text
    assert "41%" in text or "40%" in text
    assert "<code>1.2.3.4</code>" in text
    assert "target-vm" in text
    assert "5710" in text
    assert "authentication failed" in text
    assert "Failed password" in text
    assert "p=0.407" not in text
    assert "Category</b>  SSH" in text


def test_format_cowrie_alert_html():
    from modules.alert_format import format_cowrie_alert
    event = NormalizedEvent(
        src_ip="5.5.5.5",
        channel="cowrie",
        event_type="cowrie_session",
        username="admin",
        agent_name="honeypot-vm",
        location="/var/log/cowrie/cowrie.json",
        raw_ref='{"eventid":"cowrie.session.connect"}'
    )
    text = format_cowrie_alert(event)
    assert "🟡 COWRIE" in text
    assert "Category</b>  COWRIE" in text
    assert "<code>5.5.5.5</code>" in text
    assert "admin" in text
    assert "cowrie.session.connect" in text


def test_format_web_alert_html():
    from modules.alert_format import format_web_alert
    event = NormalizedEvent(
        src_ip="1.1.1.1",
        channel="web",
        event_type="sqli",
        agent_name="web-vm",
    )
    text = format_web_alert(event)
    assert "🟡 WEB" in text
    assert "Category</b>  WEB" in text
    assert "<code>1.1.1.1</code>" in text


def test_format_windows_alert_html():
    from modules.alert_format import format_windows_alert
    event = NormalizedEvent(
        channel="windows",
        event_type="windows_logon",
        agent_name="win-vm",
        wazuh_rule_id=60114,
        wazuh_rule_level=8,
        wazuh_rule_description="Windows logon success",
    )
    text = format_windows_alert(event)
    assert "🟡 WINDOWS" in text
    assert "Category</b>  WINDOWS" in text
    assert "60114" in text


def test_telegram_dedup():
    reset_dedup()
    assert should_send_telegram("1.2.3.4", "ssh") is True
    assert should_send_telegram("1.2.3.4", "ssh") is False
    assert should_send_telegram("1.2.3.4", "cowrie") is True
    assert should_send_telegram("1.2.3.4", "cowrie") is False
