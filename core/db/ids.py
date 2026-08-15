"""Time-ordered UUIDs for high-insert tables (register item STO-4).

`uuid4` is random, so every insert lands on an arbitrary B-tree leaf: page
splits, poor cache locality, and index bloat on the one table that must keep up
during an attack. UUIDv7 (RFC 9562) puts a 48-bit millisecond timestamp in the
high bits, so generated ids sort in creation order and inserts append.

Stdlib only — Python 3.14 has `uuid.uuid7()` but the project targets 3.11+, so
this is implemented locally and used unconditionally to keep behaviour identical
across versions.
"""
from __future__ import annotations

import os
import time
import uuid

_last_ms = 0
_seq = 0


def uuid7() -> uuid.UUID:
    """A time-ordered UUID (RFC 9562 v7).

    Layout: 48-bit unix_ts_ms | 4-bit version | 12-bit counter | 2-bit variant
            | 62-bit random.

    The 12-bit counter breaks ties inside a millisecond so ids generated in a
    tight loop still sort strictly — without it, a burst of inserts in the same
    millisecond would order randomly and lose most of the locality benefit.
    """
    global _last_ms, _seq

    ms = time.time_ns() // 1_000_000
    if ms == _last_ms:
        _seq = (_seq + 1) & 0xFFF
        if _seq == 0:  # counter wrapped; step the clock so ordering holds
            ms = _last_ms = _last_ms + 1
    else:
        _last_ms, _seq = ms, 0

    rand = int.from_bytes(os.urandom(8), "big") & ((1 << 62) - 1)
    value = (
        (ms & ((1 << 48) - 1)) << 80
        | 0x7 << 76           # version 7
        | (_seq & 0xFFF) << 64
        | 0b10 << 62          # RFC 4122 variant
        | rand
    )
    return uuid.UUID(int=value)


def _demo() -> None:
    ids = [str(uuid7()) for _ in range(10_000)]
    assert ids == sorted(ids), "uuid7 must be monotonically increasing"
    assert len(set(ids)) == len(ids), "uuid7 must be unique"
    assert all(uuid.UUID(i).version == 7 for i in ids), "must report version 7"
    # A v4 baseline should NOT be ordered — proves the test can actually fail.
    v4 = [str(uuid.uuid4()) for _ in range(1_000)]
    assert v4 != sorted(v4), "sanity: uuid4 should not be ordered"
    print(f"uuid7 ok — {len(ids)} ids, ordered and unique")


if __name__ == "__main__":
    _demo()
