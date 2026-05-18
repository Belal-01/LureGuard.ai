"""Tests for ml.extractor — feature engineering."""
from datetime import datetime, timezone

from ml.extractor import LureGuardExtractor, parse_event_datetime


def test_parse_event_datetime_z_suffix():
    dt = parse_event_datetime("2026-01-15T12:00:00Z")
    assert dt.tzinfo is not None
    assert dt.year == 2026


def test_single_failed_attempt_features():
    ext = LureGuardExtractor(window_seconds=300, baseline_store_path=None)
    features = ext.update_from_raw(
        src_ip="10.1.1.1",
        username="root",
        status="failed",
        event_timestamp="2026-01-15T12:00:00Z",
    )
    assert features[0] == 1.0  # f1 count
    assert features[1] == 1.0  # f2 failure ratio
    assert features[2] == 1.0  # f3 unique users
    assert features[7] == 0.0  # f8 not whitelisted


def test_burstiness_in_10s_window():
    ext = LureGuardExtractor(window_seconds=300, burst_subwindow_seconds=10)
    base = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc).timestamp()
    ip = "10.2.2.2"

    for i in range(5):
        ts = datetime.fromtimestamp(base + i, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        ext.update_from_raw(ip, "u1", "failed", ts)

    history = list(ext.ip_history[ip])
    burst = ext._compute_burstiness(history)
    assert burst == 5

    features = ext.update_from_raw(
        ip,
        "u1",
        "failed",
        datetime.fromtimestamp(base + 5, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    assert features[3] >= 5.0  # f4 burstiness


def test_whitelist_flag():
    ext = LureGuardExtractor()
    features = ext.update_from_raw(
        "10.3.3.3",
        "admin",
        "failed",
        "2026-01-15T12:00:00Z",
        is_whitelist=True,
    )
    assert features[7] == 1.0
