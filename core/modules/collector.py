"""
Collector — parses and normalizes incoming Wazuh alerts.
Input:  WazuhAlert (Pydantic)
Output: NormalizedEvent (internal schema)
"""
from schemas.wazuh_alert import WazuhAlert
from schemas.normalized_event import NormalizedEvent


# ── Channel mapping from Wazuh rule groups ────────────────
_CHANNEL_MAP = {
    "sshd": "sshd",
    "authentication_failed": "sshd",
    "authentication_success": "sshd",
    "syscheck": "syscheck",
    "rootcheck": "rootcheck",
    "lureguard_custom": "cowrie",
}

# ── Cowrie profile tag mapping ────────────────────────────
_PROFILE_KEYWORDS = {
    "dev-server": "dev-server",
    "cowrie-dev": "dev-server",
    "db-server": "db-server",
    "cowrie-db": "db-server",
}


def normalize_event(alert: WazuhAlert) -> NormalizedEvent:
    """Convert a raw Wazuh alert into a NormalizedEvent."""

    # Determine channel from rule groups
    channel = "unknown"
    for group in alert.rule.groups:
        if group in _CHANNEL_MAP:
            channel = _CHANNEL_MAP[group]
            break

    # Determine event_type
    groups = alert.rule.groups
    if "authentication_failed" in groups:
        event_type = "auth_failed"
    elif "authentication_success" in groups:
        event_type = "auth_success"
    elif "syscheck" in groups:
        event_type = "fim_change"
    elif "rootcheck" in groups:
        event_type = "rootkit_detected"
    elif "lureguard_custom" in groups:
        event_type = "cowrie_session"
    else:
        event_type = "generic"

    # Detect Cowrie profile from agent name or log path
    profile_id = None
    for keyword, pid in _PROFILE_KEYWORDS.items():
        if keyword in (alert.agent.name or "").lower():
            profile_id = pid
            break

    return NormalizedEvent(
        src_ip=alert.data.srcip,
        channel=channel,
        event_type=event_type,
        username=alert.data.srcuser,
        success=alert.data.status == "valid",
        profile_id=profile_id,
        wazuh_rule_id=alert.rule.id,
        wazuh_rule_level=alert.rule.level,
        ingestion_path="wazuh",
        syscheck_path=alert.syscheck.path if alert.syscheck else None,
        syscheck_event=alert.syscheck.event if alert.syscheck else None,
        syscheck_sha256_after=alert.syscheck.sha256_after if alert.syscheck else None,
        raw_ref=alert.full_log[:500],
    )
