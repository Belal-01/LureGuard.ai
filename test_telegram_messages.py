import sys
from pathlib import Path
from datetime import datetime

# Add core to path so imports work
core_path = Path(__file__).parent / "core"
sys.path.insert(0, str(core_path))

from schemas.normalized_event import NormalizedEvent
from schemas.decision_result import DecisionResult
from modules.alert_format import (
    format_ssh_alert,
    format_cowrie_alert,
    format_web_alert,
    format_windows_alert
)
from connectors.telegram import telegram_notifier

def main():
    print("Testing Telegram Messages...")

    # 1. Test SSH Alert
    ssh_event = NormalizedEvent(
        src_ip="192.168.1.100",
        channel="sshd",
        event_type="auth_failed",
        username="root",
        agent_name="ubuntu-prod-01",
        ts=datetime.utcnow(),
        wazuh_rule_id=5710,
        wazuh_rule_level=10,
        wazuh_rule_description="sshd: authentication failed",
        location="/var/log/auth.log",
        raw_ref="Failed password for root from 192.168.1.100 port 22 ssh2",
    )
    import uuid
    dec = DecisionResult(
        id=uuid.uuid4(),
        ts=datetime.utcnow(),
        decision="alert",
        p=0.85,
        score=0.85,
        t1=0.4,
        t2=0.7,
        model_version="1.0.0",
        features_hash="abc",
        reason="Test SSH alert",
    )
    ssh_msg = format_ssh_alert(dec, ssh_event, t1=0.4, t2=0.7)
    telegram_notifier.send_message(ssh_msg, parse_mode="HTML")
    print("✅ Sent SSH Alert")

    # 2. Test Cowrie Alert
    cowrie_event = NormalizedEvent(
        src_ip="203.0.113.45",
        channel="cowrie",
        event_type="cowrie_session",
        username="admin",
        agent_name="honeypot-01",
        ts=datetime.utcnow(),
        location="/var/log/cowrie/cowrie.json",
        raw_ref='{"eventid":"cowrie.session.connect","src_ip":"203.0.113.45","message":"New connection: 203.0.113.45"}'
    )
    cowrie_msg = format_cowrie_alert(cowrie_event)
    telegram_notifier.send_message(cowrie_msg, parse_mode="HTML")
    print("✅ Sent Cowrie Alert")

    # 3. Test Web Alert
    web_event = NormalizedEvent(
        src_ip="10.0.0.50",
        channel="web",
        event_type="SQL Injection Attempt",
        agent_name="web-server-02",
        ts=datetime.utcnow(),
        location="/var/log/nginx/access.log",
        raw_ref='GET /login.php?user=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 403 125'
    )
    web_msg = format_web_alert(web_event)
    telegram_notifier.send_message(web_msg, parse_mode="HTML")
    print("✅ Sent Web Alert")

    # 4. Test Windows Alert
    win_event = NormalizedEvent(
        src_ip="192.168.5.22",
        channel="windows",
        event_type="windows_logon",
        agent_name="win-desktop-05",
        ts=datetime.utcnow(),
        wazuh_rule_id=60114,
        wazuh_rule_level=8,
        wazuh_rule_description="Windows logon success",
        location="EventChannel",
        raw_ref='An account was successfully logged on.'
    )
    win_msg = format_windows_alert(win_event)
    telegram_notifier.send_message(win_msg, parse_mode="HTML")
    print("✅ Sent Windows Alert")

if __name__ == "__main__":
    main()
