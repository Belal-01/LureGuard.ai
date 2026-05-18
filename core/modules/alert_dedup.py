"""Suppress duplicate Telegram notifications for the same host/decision."""
from __future__ import annotations

import os
import time

_last_sent: dict[str, float] = {}


def _cooldown_seconds() -> float:
    raw = os.getenv("TELEGRAM_DEDUP_SECONDS", "90")
    try:
        return max(10.0, float(raw))
    except ValueError:
        return 90.0


def should_send_telegram(src_ip: str | None, decision: str) -> bool:
    """One Telegram per source IP per cooldown (alert+redirect share the window)."""
    _ = decision
    key = src_ip or "unknown"
    now = time.monotonic()
    last = _last_sent.get(key, 0.0)
    if now - last < _cooldown_seconds():
        return False
    _last_sent[key] = now
    return True


def reset() -> None:
    """For tests."""
    _last_sent.clear()
