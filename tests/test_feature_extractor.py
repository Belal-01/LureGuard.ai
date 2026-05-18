"""Tests for SSH feature extraction in core."""
from datetime import datetime
from pathlib import Path

import pytest

from schemas.normalized_event import NormalizedEvent


def test_extract_ssh_features_shape(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from runtime import window_store as ws

    ws.reset_extractor()
    monkeypatch.setenv("MODELS_DIR", str(tmp_path))

    from modules import feature_extractor

    event = NormalizedEvent(
        ts=datetime(2026, 5, 20, 14, 31, 2),
        src_ip="198.51.100.10",
        channel="sshd",
        event_type="auth_failed",
        username="root",
    )
    vec = feature_extractor.extract_ssh_features(event)
    assert vec.shape == (8,)
    assert vec[0] >= 1.0


def test_whitelist_sets_f8():
    from runtime import whitelist as wl
    from runtime import window_store as ws

    wl.reset_whitelist_cache()
    wl.refresh_cache(["10.0.0.1"])
    ws.reset_extractor()

    from modules import feature_extractor

    event = NormalizedEvent(
        ts=datetime(2026, 5, 20, 14, 31, 2),
        src_ip="10.0.0.1",
        channel="sshd",
        event_type="auth_failed",
        username="admin",
    )
    vec = feature_extractor.extract_ssh_features(event)
    assert vec[7] == 1.0
