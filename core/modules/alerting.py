"""
Alerting — Telegram notifications via connectors/telegram.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

from config import settings
from modules.alert_dedup import should_send_telegram
from modules.alert_format import format_non_ssh_alert, format_ssh_alert
from schemas.decision_result import DecisionResult
from schemas.normalized_event import NormalizedEvent

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from connectors.telegram import telegram_notifier  # noqa: E402


async def send_alert(decision: DecisionResult, event: NormalizedEvent) -> None:
    if not should_send_telegram(event.src_ip, decision.decision):
        logger.debug(f"Telegram deduped for {event.src_ip} ({decision.decision})")
        return

    message = format_ssh_alert(
        decision,
        event,
        t1=settings.thresholds.t1,
        t2=settings.thresholds.t2,
    )
    result = telegram_notifier.send_message(message, parse_mode="HTML")
    if not result.get("sent"):
        logger.warning(f"Telegram not sent: {result.get('reason')}")
    else:
        logger.info(f"Telegram sent for {event.src_ip} ({decision.decision}, p={decision.p:.3f})")


async def send_non_ssh_alert(event: NormalizedEvent) -> None:
    if not should_send_telegram(event.src_ip or event.channel, event.event_type):
        logger.debug(f"Telegram deduped for {event.channel}/{event.event_type}")
        return

    message = format_non_ssh_alert(event)
    result = telegram_notifier.send_message(message, parse_mode="HTML")
    if not result.get("sent"):
        logger.warning(f"Telegram not sent: {result.get('reason')}")
