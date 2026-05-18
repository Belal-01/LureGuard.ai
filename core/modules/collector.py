"""
Collector — parses and normalizes incoming Wazuh alerts.
Input:  WazuhAlert (Pydantic)
Output: NormalizedEvent (internal schema)
"""
import re

from ml.extractor import parse_event_datetime

from schemas.wazuh_alert import WazuhAlert
from schemas.normalized_event import NormalizedEvent

_CHANNEL_MAP = {
    "sshd": "sshd",
    "authentication_failed": "sshd",
    "authentication_success": "sshd",
    "syscheck": "syscheck",
    "rootcheck": "rootcheck",
    "lureguard_custom": "cowrie",
}

_PROFILE_KEYWORDS = {
    "dev-server": "dev-server",
    "cowrie-dev": "dev-server",
    "db-server": "db-server",
    "cowrie-db": "db-server",
}

_SSH_FAIL_RULE_IDS = {5710, 5712, 5760}


def normalize_event(alert: WazuhAlert) -> NormalizedEvent:
    groups = alert.rule_groups
    full_log = (alert.full_log or "").lower()

    channel = "unknown"
    for group in groups:
        if group in _CHANNEL_MAP:
            channel = _CHANNEL_MAP[group]
            break
    if channel == "unknown" and ("sshd" in groups or "sshd" in full_log):
        channel = "sshd"

    if "syscheck" in groups:
        event_type = "fim_change"
    elif "rootcheck" in groups:
        event_type = "rootkit_detected"
    elif "lureguard_custom" in groups:
        event_type = "cowrie_session"
    elif "authentication_failed" in groups:
        event_type = "auth_failed"
    elif "authentication_success" in groups:
        event_type = "auth_success"
    elif alert.rule_id in _SSH_FAIL_RULE_IDS:
        event_type = "auth_failed"
    elif "failed password" in full_log or "authentication failure" in full_log:
        event_type = "auth_failed"
    elif "accepted password" in full_log or "accepted publickey" in full_log:
        event_type = "auth_success"
    else:
        event_type = "generic"

    profile_id = None
    agent_name = str(alert.agent.get("name", "")).lower()
    for keyword, pid in _PROFILE_KEYWORDS.items():
        if keyword in agent_name:
            profile_id = pid
            break

    data = alert.data
    status = str(data.get("status", "")).lower()
    success = status in ("valid", "success")

    syscheck = alert.syscheck or {}

    event_ts = parse_event_datetime(alert.timestamp or None)

    full_log = (alert.full_log or "").strip()
    username = data.get("srcuser")
    if not username and full_log:
        user_match = re.search(r"\buser=(\S+)", full_log)
        if user_match:
            username = user_match.group(1)

    return NormalizedEvent(
        ts=event_ts.replace(tzinfo=None),
        src_ip=data.get("srcip"),
        channel=channel,
        event_type=event_type,
        username=username,
        success=success,
        profile_id=profile_id,
        wazuh_rule_id=alert.rule_id,
        wazuh_rule_level=alert.rule_level,
        wazuh_rule_description=alert.rule_description or None,
        agent_name=alert.agent_name or None,
        agent_id=alert.agent_id_str or None,
        agent_ip=alert.agent_ip or None,
        location=alert.location or None,
        ingestion_path="wazuh",
        syscheck_path=syscheck.get("path"),
        syscheck_event=syscheck.get("event"),
        syscheck_sha256_after=syscheck.get("sha256_after"),
        raw_ref=full_log[:500],
    )
