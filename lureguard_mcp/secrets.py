"""Redact sensitive values before audit logging."""

from __future__ import annotations

import re
from typing import Any

_SECRET_KEY_RE = re.compile(
    r"(password|passwd|token|api[_-]?key|secret|credential|authorization)",
    re.IGNORECASE,
)

_REDACTED = "***REDACTED***"


def _is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(key))


def redact_value(key: str, value: Any) -> Any:
    if _is_secret_key(key):
        return _REDACTED
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, list):
        return [redact_value(key, item) for item in value]
    return value


def redact_mapping(data: dict[str, Any] | None) -> dict[str, Any]:
    if not data:
        return {}
    out: dict[str, Any] = {}
    for key, value in data.items():
        if _is_secret_key(key):
            out[key] = _REDACTED
        elif isinstance(value, dict):
            out[key] = redact_mapping(value)
        elif isinstance(value, list):
            out[key] = [
                redact_mapping(item) if isinstance(item, dict) else redact_value(key, item)
                for item in value
            ]
        else:
            out[key] = value
    return out


def redact_ssh_output(text: str, *, max_len: int = 500) -> str:
    """Truncate and mark SSH/sudo output — may contain secrets."""
    if not text:
        return ""
    trimmed = text[:max_len]
    if len(text) > max_len:
        trimmed += "…[truncated]"
    return f"[ssh-output]{trimmed}"
