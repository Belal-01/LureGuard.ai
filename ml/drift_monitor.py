from __future__ import annotations

import json
import math
from collections import deque
from pathlib import Path
from typing import Dict, List

from ml.feature_contract import FEATURE_DRIFT_COLUMNS


class FeatureDriftMonitor:
    def __init__(
        self,
        baseline_path: Path,
        min_samples: int = 200,
        major_threshold: float = 0.25,
        moderate_threshold: float = 0.10,
    ):
        self.baseline_path = Path(baseline_path)
        self.min_samples = min_samples
        self.major_threshold = major_threshold
        self.moderate_threshold = moderate_threshold
        self._baseline = self._load_baseline()
        self._buffers = {feature: deque(maxlen=5000) for feature in FEATURE_DRIFT_COLUMNS}

    def _load_baseline(self) -> Dict[str, dict] | None:
        if not self.baseline_path.exists():
            return None
        payload = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        return payload.get("features")

    @property
    def enabled(self) -> bool:
        return self._baseline is not None

    def _safe_hist(self, values: List[float], edges: List[float]) -> List[float]:
        if len(edges) < 2:
            return [1.0]
        bins = [0 for _ in range(len(edges) - 1)]
        for v in values:
            idx = len(edges) - 2
            for i in range(len(edges) - 1):
                lo, hi = edges[i], edges[i + 1]
                is_last = i == len(edges) - 2
                if (v >= lo and v < hi) or (is_last and v == hi):
                    idx = i
                    break
            bins[idx] += 1

        total = max(sum(bins), 1)
        return [c / total for c in bins]

    def _psi(self, expected: List[float], actual: List[float], epsilon: float = 1e-6) -> float:
        score = 0.0
        for e, a in zip(expected, actual):
            e_adj = max(e, epsilon)
            a_adj = max(a, epsilon)
            score += (a_adj - e_adj) * math.log(a_adj / e_adj)
        return float(score)

    def update(self, feature_map: Dict[str, float]) -> Dict[str, object] | None:
        if not self.enabled:
            return None

        for feature in FEATURE_DRIFT_COLUMNS:
            if feature in feature_map:
                self._buffers[feature].append(float(feature_map[feature]))

        if any(len(self._buffers[feature]) < self.min_samples for feature in FEATURE_DRIFT_COLUMNS):
            return {
                "enabled": True,
                "ready": False,
                "min_samples": self.min_samples,
                "current_samples": min(len(self._buffers[f]) for f in FEATURE_DRIFT_COLUMNS),
            }

        psi_scores: Dict[str, float] = {}
        for feature in FEATURE_DRIFT_COLUMNS:
            baseline = self._baseline.get(feature)
            if not baseline:
                continue
            expected = baseline.get("expected", [])
            edges = baseline.get("bin_edges", [])
            current = list(self._buffers[feature])
            actual = self._safe_hist(current, edges)
            psi_scores[feature] = self._psi(expected, actual)

        max_psi = max(psi_scores.values()) if psi_scores else 0.0
        if max_psi >= self.major_threshold:
            level = "high"
        elif max_psi >= self.moderate_threshold:
            level = "moderate"
        else:
            level = "low"

        return {
            "enabled": True,
            "ready": True,
            "psi": psi_scores,
            "max_psi": max_psi,
            "drift_level": level,
            "thresholds": {
                "moderate": self.moderate_threshold,
                "high": self.major_threshold,
            },
        }
