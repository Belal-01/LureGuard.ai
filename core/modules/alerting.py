"""
Alerting — Telegram notifications via connectors/telegram.py
"""
from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

from loguru import logger

from config import settings
from modules.alert_dedup import should_send_telegram
from modules.alert_format import (
    format_evidence_alert,
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

_ATTEMPTS_RE = re.compile(r"attempts=(\d+)")


def _ssh_evidence(decision: DecisionResult, event: NormalizedEvent) -> dict:
    """Pull the evidence for format_evidence_alert out of what's already computed.

    attempts comes back out of DecisionResult.reason (decision_policy already
    counted it via the rolling-window extractor — no need to recompute it
    here). usernames/window come from that same extractor's in-memory window
    for this IP, which is still live when the alert is sent moments later.

    first_seen_days is NOT wired: it needs cross-day history (a DB query
    keyed on src_ip), and send_alert only receives (decision, event) — no db
    session reaches this call. Rather than invent a placeholder, we omit it;
    format_evidence_alert already renders fine without it.
    """
    m = _ATTEMPTS_RE.search(decision.reason or "")
    attempts = int(m.group(1)) if m else 1

    window_seconds = settings.window_seconds
    usernames = [event.username] if event.username else []
    try:
        from runtime.window_store import get_extractor

        history = list(get_extractor().ip_history.get(event.src_ip or "", []))
        if history:
            window_seconds = max(1, round(history[-1].ts - history[0].ts)) or settings.window_seconds
            usernames = list(dict.fromkeys(h.user for h in history))
    except Exception:
        pass  # best-effort enrichment only — attempts count still renders without it

    return {"attempts": attempts, "window_seconds": window_seconds, "usernames": usernames}


async def send_alert(decision: DecisionResult, event: NormalizedEvent) -> None:
    if not should_send_telegram(event.src_ip, "ssh"):
        logger.debug(f"Telegram deduped for {event.src_ip} ({decision.decision})")
        return

    message = format_evidence_alert(event, **_ssh_evidence(decision, event))
    result = await asyncio.to_thread(telegram_notifier.send_message, message, parse_mode="HTML")
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

    result = await asyncio.to_thread(telegram_notifier.send_message, message, parse_mode="HTML")
    if not result.get("sent"):
        logger.warning(f"Telegram not sent: {result.get('reason')}")
