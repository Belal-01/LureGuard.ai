"""Investigation context for MCP tool audit logging."""

from __future__ import annotations

import contextvars
from typing import Any

current_investigation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_investigation_id", default=None
)


def set_investigation_id(inv_id: str | None) -> None:
    current_investigation_id.set(inv_id)


def get_investigation_id() -> str | None:
    return current_investigation_id.get()
