from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

FEATURE_COLUMNS = ["f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8"]
FEATURE_DRIFT_COLUMNS = ["f4", "f5", "f6", "f7", "f8"]


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    description: str
    formula: str
    unit: str
    window_seconds: int


FEATURE_CONTRACT: Dict[str, FeatureSpec] = {
    "f1": FeatureSpec(
        name="f1",
        description="Total authentication attempts inside the rolling window.",
        formula="count(events in last window_seconds)",
        unit="count",
        window_seconds=300,
    ),
    "f2": FeatureSpec(
        name="f2",
        description="Failure ratio inside the rolling window.",
        formula="failed_attempts / total_attempts",
        unit="ratio [0,1]",
        window_seconds=300,
    ),
    "f3": FeatureSpec(
        name="f3",
        description="Distinct usernames attempted from the same source IP in window.",
        formula="cardinality(unique usernames)",
        unit="count",
        window_seconds=300,
    ),
    "f4": FeatureSpec(
        name="f4",
        description="Burstiness: maximum attempts observed in any 10-second sub-window.",
        formula="max(count(events between t and t+10s))",
        unit="count",
        window_seconds=300,
    ),
    "f5": FeatureSpec(
        name="f5",
        description="Mean inter-arrival time between consecutive attempts.",
        formula="mean(diff(sorted event timestamps))",
        unit="seconds",
        window_seconds=300,
    ),
    "f6": FeatureSpec(
        name="f6",
        description="Standard deviation of inter-arrival times.",
        formula="std(diff(sorted event timestamps))",
        unit="seconds",
        window_seconds=300,
    ),
    "f7": FeatureSpec(
        name="f7",
        description="Temporal risk weight from historical hour/day baseline (UTC).",
        formula="sigmoid((current_rate - baseline_mean) / baseline_std)",
        unit="ratio [0,1]",
        window_seconds=300,
    ),
    "f8": FeatureSpec(
        name="f8",
        description="Whitelist flag from IP/CIDR + optional user + optional expiry policy.",
        formula="1.0 if whitelist rule matches else 0.0",
        unit="binary {0,1}",
        window_seconds=300,
    ),
}


def feature_contract_rows() -> List[dict]:
    return [
        {
            "feature": spec.name,
            "description": spec.description,
            "formula": spec.formula,
            "unit": spec.unit,
            "window_seconds": spec.window_seconds,
        }
        for spec in FEATURE_CONTRACT.values()
    ]
