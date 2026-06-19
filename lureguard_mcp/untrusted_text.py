"""Sanitize attacker-controlled text before it reaches the LLM via MCP tools."""

from __future__ import annotations

import re
from typing import Any

# Fields that may contain attacker-controlled content from ingested alerts.
UNTRUSTED_EVENT_FIELDS = frozenset(
    {
        "username",
        "raw_ref",
        "syscheck_path",
        "syscheck_event",
        "wazuh_rule_description",
        "agent_name",
        "geo_country",
        "geo_city",
        "finding",
        "citation",
        "description",
        "ioc_value",
        "notes",
        "reason",
    }
)

_PROMPT_INJECTION_PATTERNS = (
    re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior)\s+instructions?\b"),
    re.compile(r"(?i)\bsystem\s*:\s*"),
    re.compile(r"(?i)\bassistant\s*:\s*"),
    re.compile(r"(?i)\buser\s*:\s*"),
    re.compile(r"(?i)\bdeveloper\s+message\b"),
    re.compile(r"(?i)\bdo\s+not\s+follow\b"),
    re.compile(r"(?i)\boverride\s+(safety|policy|instructions?)\b"),
)

_MAX_FIELD_LEN = 2000


def sanitize_untrusted_text(value: Any, *, max_len: int = _MAX_FIELD_LEN) -> Any:
    """Neutralize prompt-control patterns and fence-breakers in untrusted strings."""
    if value is None:
        return None
    if not isinstance(value, str):
        return value

    text = value.replace("\r\n", "\n").replace("\r", "\n")
    for pattern in _PROMPT_INJECTION_PATTERNS:
        text = pattern.sub("[filtered]", text)

    # Reduce markdown/code-fence breakout attempts.
    text = text.replace("```", "'''")
    if len(text) > max_len:
        text = text[:max_len] + "…[truncated]"
    return text


def shape_event_row(row: dict[str, Any]) -> dict[str, Any]:
    """Apply sanitization to known untrusted fields on an event dict."""
    out = dict(row)
    for key in UNTRUSTED_EVENT_FIELDS:
        if key in out:
            out[key] = sanitize_untrusted_text(out[key])
    return out


def wrap_untrusted_block(label: str, payload: str) -> str:
    """Wrap untrusted content in explicit delimiters for LLM prompts."""
    safe = sanitize_untrusted_text(payload or "", max_len=1500)
    return f"<<<UNTRUSTED_{label}>>>\n{safe}\n<<<END_UNTRUSTED_{label}>>>"
