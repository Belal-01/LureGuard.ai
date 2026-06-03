"""
Alerting — Telegram notifications via connectors/telegram.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

from config import settings
from modules.alert_dedup import should_send_telegram
from modules.alert_format import (
    format_ssh_alert,
    format_fim_alert,
    format_cowrie_alert,
    format_web_alert,
    format_windows_alert,
)
from schemas.decision_result import DecisionResult
from schemas.normalized_event import NormalizedEvent

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from connectors.telegram import telegram_notifier  # noqa: E402


async def send_alert(decision: DecisionResult, event: NormalizedEvent) -> None:
    if not should_send_telegram(event.src_ip, "ssh"):
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
    category = "fim"
    if event.channel in ("cowrie", "cowrie_session") or event.event_type == "cowrie_session":
        category = "cowrie"
    elif event.channel == "web":
        category = "web"
    elif event.channel == "windows":
        category = "windows"

    if not should_send_telegram(event.src_ip or event.channel, category):
        logger.debug(f"Telegram deduped for {event.channel}/{event.event_type} (category: {category})")
        return

    if category == "cowrie":
        message = format_cowrie_alert(event)
    elif category == "web":
        message = format_web_alert(event)
    elif category == "windows":
        message = format_windows_alert(event)
    else:
        message = format_fim_alert(event)

    result = telegram_notifier.send_message(message, parse_mode="HTML")
    if not result.get("sent"):
        logger.warning(f"Telegram not sent: {result.get('reason')}")
