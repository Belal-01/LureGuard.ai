from __future__ import annotations

import json
import mimetypes
import os
from pathlib import Path
from urllib import parse, request

import httpx

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SECRETS_DIR = _REPO_ROOT / "secrets"
_DOCUMENT_TIMEOUT_SECONDS = 30.0


def _read_secret_file(filename: str) -> str:
    path = _SECRETS_DIR / filename
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


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
        self.token = (
            os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
            or _read_secret_file("telegram_token.txt")
        )
        self.chat_id = (
            os.getenv("TELEGRAM_CHAT_ID", "").strip()
            or _read_secret_file("telegram_chat_id.txt")
        )
        self.message_thread_id = os.getenv("TELEGRAM_MESSAGE_THREAD_ID", "").strip()
        self.timeout_seconds = _get_float_env("TELEGRAM_TIMEOUT_SECONDS", 3.0)

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send_message(self, message: str, *, parse_mode: str | None = None) -> dict:
        if not self.enabled:
            return {"sent": False, "reason": "telegram_not_configured"}

        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        fields: dict[str, str] = {"chat_id": self.chat_id, "text": message}
        if self.message_thread_id:
            fields["message_thread_id"] = self.message_thread_id
        if parse_mode:
            fields["parse_mode"] = parse_mode
        body = parse.urlencode(fields).encode("utf-8")

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

    def send_document(
        self,
        file_path: str | Path,
        *,
        caption: str = "",
        filename: str | None = None,
    ) -> dict:
        """Upload a file to the configured Telegram chat (sendDocument)."""
        if not self.enabled:
            return {"sent": False, "reason": "telegram_not_configured"}

        path = Path(file_path)
        if not path.is_file():
            return {"sent": False, "reason": f"file_not_found: {path}"}

        upload_name = filename or path.name
        mime_type = mimetypes.guess_type(upload_name)[0] or "application/octet-stream"
        url = f"https://api.telegram.org/bot{self.token}/sendDocument"

        data: dict[str, str] = {"chat_id": self.chat_id}
        if caption.strip():
            data["caption"] = caption.strip()[:1024]
        if self.message_thread_id:
            data["message_thread_id"] = self.message_thread_id

        try:
            with path.open("rb") as handle:
                files = {"document": (upload_name, handle, mime_type)}
                response = httpx.post(
                    url,
                    data=data,
                    files=files,
                    timeout=_DOCUMENT_TIMEOUT_SECONDS,
                )
            payload = response.json()
            is_ok = bool(payload.get("ok"))
            result: dict[str, str | bool] = {
                "sent": is_ok,
                "reason": "ok" if is_ok else "telegram_api_error",
                "file_path": str(path),
                "filename": upload_name,
            }
            if not is_ok:
                result["detail"] = str(payload.get("description", ""))
            return result
        except Exception as exc:
            return {
                "sent": False,
                "reason": f"telegram_send_failed: {type(exc).__name__}",
                "file_path": str(path),
            }


telegram_notifier = TelegramNotifier()
