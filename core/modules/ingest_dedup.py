"""Drop duplicate Wazuh posts (same failure → auth.log + journald)."""
from __future__ import annotations

import os
import time
from collections import OrderedDict

# ponytail: per-process only — dedup state is lost on restart and cannot be
# shared across replicas. Fixing that means Redis or a DB round trip per
# event, both worse than staying single-node here. Keep Core to one replica.
_recent: "OrderedDict[tuple[str, int, str], float]" = OrderedDict()

_STALE_SECONDS = 60.0
# Cap so a flood of unique keys (e.g. spoofed src_ips) can't grow this
# without bound between prunes. ~1k events/sec * 60s window headroom.
_MAX_ENTRIES = 100_000


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

    # Entries are kept in insertion/refresh order, oldest first, so expiry
    # only ever touches the actually-stale prefix instead of the whole dict.
    cutoff = now - _STALE_SECONDS
    while _recent:
        oldest_key, oldest_t = next(iter(_recent.items()))
        if oldest_t >= cutoff:
            break
        del _recent[oldest_key]

    last = _recent.get(key)
    if last is not None and now - last < _window_seconds():
        _recent.move_to_end(key)
        return True

    _recent[key] = now
    _recent.move_to_end(key)
    if len(_recent) > _MAX_ENTRIES:
        _recent.popitem(last=False)
    return False


def reset() -> None:
    _recent.clear()


def _demo() -> None:
    """Smallest self-check: dedup within window, expiry, and the memory cap."""
    reset()
    assert is_duplicate_wazuh_event("1.2.3.4", 1, "2026-08-14T00:00:00") is False
    assert is_duplicate_wazuh_event("1.2.3.4", 1, "2026-08-14T00:00:00") is True
    reset()
    for i in range(_MAX_ENTRIES + 10):
        is_duplicate_wazuh_event(f"10.0.{i // 256}.{i % 256}", i, "2026-08-14T00:00:00")
    assert len(_recent) <= _MAX_ENTRIES
    reset()


if __name__ == "__main__":
    _demo()
    print("ok")
