"""
ML-1/ML-2: the behavioural feature contract.

These eight features are the *only* thing the model scores. That is the point,
not an accident:

  * ML-1 — none of them derives from `rule_level`, `rule_id`, `decoder` or any
    other Wazuh field. The previous model scored 24 columns, three of which
    were Wazuh's own verdict, and reported 0.9996 precision for predicting
    severity from severity. Excluding the verdict *structurally* — by it not
    being in the contract at all — is the only version of that fix which
    cannot quietly come back.
  * ML-2 — every one of them is computed from the source's recent history, so
    two events with identical Wazuh metadata and different attack histories
    produce different rows. Wazuh metadata alone cannot do that; it is a
    property of the event, not of the behaviour around it.

Channel-generic on purpose. Brute force and web scanning are the same shape —
one source, many failed attempts against many targets, in a short window — and
the only channel-specific part is what "target" means:

    sshd  -> username attempted
    web   -> request path attempted

so the contract names it `target` and `modules.feature_extractor` picks the
field. That generalisation is what lets one model cover both channels instead
of one auth-shaped model that cannot see a scan.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

# Fixed at 8. `modules.inference` falls back to this list when a registry
# declares no columns, and tests/test_inference.py pins the length.
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
        description=(
            "Requests from this source inside the rolling window — login "
            "attempts on sshd, HTTP requests on web."
        ),
        formula="count(events from src_ip in last window_seconds)",
        unit="count",
        window_seconds=300,
    ),
    "f2": FeatureSpec(
        name="f2",
        description=(
            "Failure ratio inside the window — failed logins on sshd, 4xx/5xx "
            "responses on web. A scanner fails almost everything it tries; a "
            "real user mostly succeeds."
        ),
        formula="failed_events / total_events",
        unit="ratio [0,1]",
        window_seconds=300,
    ),
    "f3": FeatureSpec(
        name="f3",
        description=(
            "Distinct targets attempted from this source in the window — "
            "usernames on sshd, request paths on web. This is what separates a "
            "sweep from a retry: a broken bookmark hammers one target, a "
            "scanner walks many."
        ),
        formula="cardinality(unique targets)",
        unit="count",
        window_seconds=300,
    ),
    "f4": FeatureSpec(
        name="f4",
        description="Burstiness: maximum events observed in any 10-second sub-window.",
        formula="max(count(events between t and t+10s))",
        unit="count",
        window_seconds=300,
    ),
    "f5": FeatureSpec(
        name="f5",
        description=(
            "Mean inter-arrival time between consecutive events from this "
            "source. Automation is fast; a human is not."
        ),
        formula="mean(diff(sorted event timestamps))",
        unit="seconds",
        window_seconds=300,
    ),
    "f6": FeatureSpec(
        name="f6",
        description=(
            "Standard deviation of inter-arrival times. Near-zero means a fixed "
            "cadence — which is a scanner's loop, but also a health check's "
            "cron, so it only means something next to f2 and f3."
        ),
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
