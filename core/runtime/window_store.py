from __future__ import annotations

from ml.extractor import LureGuardExtractor

from config import settings
from runtime.paths import models_dir

_extractor: LureGuardExtractor | None = None


def get_extractor() -> LureGuardExtractor:
    global _extractor
    if _extractor is None:
        baseline_path = models_dir() / "temporal_baseline.json"
        _extractor = LureGuardExtractor(
            window_seconds=settings.window_seconds,
            burst_subwindow_seconds=10,
            baseline_min_count=30,
            baseline_store_path=baseline_path if baseline_path.exists() else None,
        )
    return _extractor


def reset_extractor() -> None:
    global _extractor
    _extractor = None
