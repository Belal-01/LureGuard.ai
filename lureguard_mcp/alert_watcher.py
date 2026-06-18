"""Always-on alert watcher — polls high-level events and triggers triage."""

from __future__ import annotations

import logging
import subprocess
import threading
from datetime import datetime, timedelta

from lureguard_mcp.config import REPO_ROOT, auto_triage_level
from lureguard_mcp.db import get_high_level_events_since_db, mark_event_watched_db

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 30
_watcher_thread: threading.Thread | None = None
_stop_event = threading.Event()
_last_checked: datetime | None = None


def _notify_telegram(message: str) -> None:
    try:
        from connectors.telegram import telegram_notifier

        telegram_notifier.send_message(message)
    except Exception as exc:
        logger.warning("Telegram notify failed: %s", exc)


def _run_auto_triage(event: dict) -> None:
    src_ip = event.get("src_ip") or "unknown"
    level = event.get("wazuh_rule_level")
    desc = event.get("wazuh_rule_description") or event.get("event_type")
    prompt = (
        f"Read skills/triage.md. A Wazuh alert fired automatically: "
        f"src_ip={src_ip}, level={level}, rule={desc}, event_id={event.get('id')}. "
        f"Open investigation, enrich with get_ip_context, triage, and close with findings."
    )
    cmd = ["opencode", "run", prompt]
    try:
        subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.warning("opencode not found — skipping auto-triage subprocess")


def _poll_once() -> None:
    global _last_checked
    since = _last_checked or (datetime.utcnow() - timedelta(minutes=5))
    min_level = auto_triage_level()
    events = get_high_level_events_since_db(since, min_level)
    for event in events:
        event_id = str(event.get("id", ""))
        if not event_id:
            continue
        mark_event_watched_db(event_id)
        summary = (
            f"LureGuard auto-triage: level {event.get('wazuh_rule_level')} "
            f"from {event.get('src_ip')} — {event.get('wazuh_rule_description') or event.get('channel')}"
        )
        _notify_telegram(summary)
        _run_auto_triage(event)
        logger.info("Auto-triage triggered for event %s", event_id)
    _last_checked = datetime.utcnow()


def _watcher_loop() -> None:
    logger.info("Alert watcher started (min_level=%s)", auto_triage_level())
    while not _stop_event.is_set():
        try:
            _poll_once()
        except Exception as exc:
            logger.exception("Alert watcher poll error: %s", exc)
        _stop_event.wait(POLL_INTERVAL_SECONDS)


def start_alert_watcher() -> None:
    global _watcher_thread
    if _watcher_thread is not None and _watcher_thread.is_alive():
        return
    _stop_event.clear()
    _watcher_thread = threading.Thread(target=_watcher_loop, name="alert-watcher", daemon=True)
    _watcher_thread.start()


def stop_alert_watcher() -> None:
    _stop_event.set()
