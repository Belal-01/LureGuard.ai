from __future__ import annotations

import json
import os
from urllib import parse, request


def _get_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


class TelegramNotifier:
    def __init__(self) -> None:
        self.token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        self.timeout_seconds = _get_float_env("TELEGRAM_TIMEOUT_SECONDS", 3.0)

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send_message(self, message: str) -> dict:
        if not self.enabled:
            return {"sent": False, "reason": "telegram_not_configured"}

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        body = parse.urlencode({"chat_id": self.chat_id, "text": message}).encode("utf-8")

        req = request.Request(url=url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))

            is_ok = bool(payload.get("ok"))
            return {
                "sent": is_ok,
                "reason": "ok" if is_ok else "telegram_api_error",
            }
        except Exception as exc:
            return {
                "sent": False,
                "reason": f"telegram_send_failed: {type(exc).__name__}",
            }

    def send_alert(self, message: str) -> dict:
        return self.send_message(message)


telegram_notifier = TelegramNotifier()
