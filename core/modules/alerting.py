"""
Alerting — sends Telegram notifications.

⚠️  STUB — بلال يكمل التنفيذ في Sprint 3.
"""
from loguru import logger
from schemas.decision_result import DecisionResult
from schemas.normalized_event import NormalizedEvent


async def send_alert(decision: DecisionResult, event: NormalizedEvent) -> None:
    """Send SSH Alert/Redirect notification to Telegram."""
    logger.info(
        f"[TELEGRAM STUB] {decision.decision.upper()} "
        f"{event.src_ip} p={decision.p:.3f} → {decision.profile_id}"
    )


async def send_non_ssh_alert(event: NormalizedEvent) -> None:
    """Send FIM / Rootkit notification to Telegram."""
    logger.info(
        f"[TELEGRAM STUB] {event.channel.upper()} "
        f"{event.syscheck_path or 'unknown'} level={event.wazuh_rule_level}"
    )
