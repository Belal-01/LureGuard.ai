from __future__ import annotations

import json
import math
import statistics
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, Optional


@dataclass
class EventRecord:
    ts: float
    user: str
    failed: bool


@dataclass
class RunningStats:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    @property
    def variance(self) -> float:
        if self.n < 2:
            return 0.0
        return self.m2 / (self.n - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def update(self, value: float) -> None:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.m2 += delta * delta2


def parse_event_datetime(raw_timestamp: str | None) -> datetime:
    if not raw_timestamp:
        return datetime.now(tz=timezone.utc)

    value = raw_timestamp.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return datetime.now(tz=timezone.utc)

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class LureGuardExtractor:
    def __init__(
        self,
        window_seconds: int = 300,
        burst_subwindow_seconds: int = 10,
        baseline_min_count: int = 30,
        baseline_store_path: Optional[Path] = None,
    ):
        self.window_seconds = window_seconds
        self.burst_subwindow_seconds = burst_subwindow_seconds
        self.baseline_min_count = baseline_min_count

        self.ip_history: Dict[str, Deque[EventRecord]] = {}
        self.temporal_baseline: Dict[str, RunningStats] = {}

        self._baseline_store_path = Path(baseline_store_path) if baseline_store_path else None
        self._updates_since_persist = 0
        self._persist_every_n_updates = 100

        self._load_temporal_baseline()

    def _load_temporal_baseline(self) -> None:
        if self._baseline_store_path is None or not self._baseline_store_path.exists():
            return

        payload = json.loads(self._baseline_store_path.read_text(encoding="utf-8"))
        stats_payload = payload.get("slots", {})
        restored: Dict[str, RunningStats] = {}
        for key, data in stats_payload.items():
            restored[key] = RunningStats(
                n=int(data.get("n", 0)),
                mean=float(data.get("mean", 0.0)),
                m2=float(data.get("m2", 0.0)),
            )
        self.temporal_baseline = restored

    def _persist_temporal_baseline(self) -> None:
        if self._baseline_store_path is None:
            return

        payload = {
            "slots": {
                key: {"n": stats.n, "mean": stats.mean, "m2": stats.m2}
                for key, stats in self.temporal_baseline.items()
            }
        }
        self._baseline_store_path.parent.mkdir(parents=True, exist_ok=True)
        self._baseline_store_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _slot_key(self, event_dt: datetime) -> str:
        # weekday: Monday=0..Sunday=6 and hour in UTC.
        return f"{event_dt.weekday()}:{event_dt.hour}"

    def _trim_window(self, src_ip: str, current_ts: float) -> None:
        history = self.ip_history[src_ip]
        while history and (current_ts - history[0].ts > self.window_seconds):
            history.popleft()

    def _compute_burstiness(self, events: list[EventRecord]) -> int:
        if not events:
            return 0

        left = 0
        max_count = 1
        timestamps = [event.ts for event in events]

        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > self.burst_subwindow_seconds:
                left += 1
            max_count = max(max_count, right - left + 1)

        return max_count

    def _compute_inter_arrival(self, events: list[EventRecord]) -> tuple[float, float]:
        if len(events) < 2:
            return 0.0, 0.0

        diffs = [events[i].ts - events[i - 1].ts for i in range(1, len(events))]
        mean_gap = float(statistics.fmean(diffs))
        std_gap = float(statistics.pstdev(diffs)) if len(diffs) > 1 else 0.0
        return mean_gap, std_gap

    def _compute_temporal_weight(self, slot_key: str, attempts_per_minute: float) -> float:
        stats = self.temporal_baseline.get(slot_key)
        if not stats or stats.n < self.baseline_min_count or stats.std < 1e-6:
            return 0.5

        z_score = (attempts_per_minute - stats.mean) / stats.std
        z_score = max(min(z_score, 8.0), -8.0)
        return float(1.0 / (1.0 + math.exp(-z_score)))

    def _update_temporal_baseline(self, slot_key: str, attempts_per_minute: float) -> None:
        if slot_key not in self.temporal_baseline:
            self.temporal_baseline[slot_key] = RunningStats()
        self.temporal_baseline[slot_key].update(attempts_per_minute)

        self._updates_since_persist += 1
        if self._updates_since_persist >= self._persist_every_n_updates:
            self._persist_temporal_baseline()
            self._updates_since_persist = 0

    def update_from_raw(
        self,
        src_ip: str,
        username: str,
        status: str,
        event_timestamp: str | None,
        is_whitelist: bool = False,
    ):
        event_dt = parse_event_datetime(event_timestamp)
        event_ts = event_dt.timestamp()

        if src_ip not in self.ip_history:
            self.ip_history[src_ip] = deque()

        self.ip_history[src_ip].append(
            EventRecord(
                ts=event_ts,
                user=username or "unknown",
                failed=str(status).lower() == "failed",
            )
        )
        self._trim_window(src_ip, event_ts)

        events = list(self.ip_history[src_ip])

        f1 = len(events)
        failed_attempts = sum(1 for event in events if event.failed)
        f2 = failed_attempts / f1 if f1 > 0 else 0.0
        f3 = len({event.user for event in events})

        f4 = self._compute_burstiness(events)
        f5, f6 = self._compute_inter_arrival(events)

        attempts_per_minute = f1 / max(self.window_seconds / 60.0, 1e-9)
        slot = self._slot_key(event_dt)
        f7 = self._compute_temporal_weight(slot, attempts_per_minute)

        f8 = 1.0 if is_whitelist else 0.0

        self._update_temporal_baseline(slot, attempts_per_minute)

        return [float(f1), float(f2), float(f3), float(f4), float(f5), float(f6), float(f7), float(f8)]

    def update_and_extract(self, alert: "WazuhAlert", is_whitelist: bool = False):
        src_ip = str(alert.data.get("srcip", "0.0.0.0"))
        username = str(alert.data.get("srcuser", "unknown"))
        status = str(alert.data.get("status", "unknown"))
        event_timestamp = getattr(alert, "timestamp", None)

        return self.update_from_raw(
            src_ip=src_ip,
            username=username,
            status=status,
            event_timestamp=event_timestamp,
            is_whitelist=is_whitelist,
        )
