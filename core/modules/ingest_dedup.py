"""Drop duplicate Wazuh posts (same failure → auth.log + journald)."""
from __future__ import annotations

import os
import time

_recent: dict[tuple[str, int, str], float] = {}


def _window_seconds() -> float:
    raw = os.getenv("INGEST_DEDUP_SECONDS", "5")
    try:
        return max(1.0, float(raw))
    except ValueError:
        return 5.0


def is_duplicate_wazuh_event(src_ip: str | None, rule_id: int, timestamp: str) -> bool:
    """True if the same alert was seen in the last few seconds."""
    ts_key = (timestamp or "")[:19]
    key = (src_ip or "unknown", rule_id, ts_key)
    now = time.monotonic()
    last = _recent.get(key)
    if last is not None and now - last < _window_seconds():
        return True
    _recent[key] = now
    # prune stale
    cutoff = now - 60.0
    stale = [k for k, t in _recent.items() if t < cutoff]
    for k in stale:
        del _recent[k]
    return False


def reset() -> None:
    _recent.clear()
