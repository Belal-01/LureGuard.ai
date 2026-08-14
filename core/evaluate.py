"""
VER-1: evaluation harness. Scores the product's own decision path —
modules.decision_policy.decide() over modules.inference.infer_event() —
against the demo dataset's generator-known labels, offline, no database.

Label source: demo_seed.generate_events()'s `is_attack_scenario` flag, set
only on the rows the generator built as the SSH brute-force story. That flag
never touches wazuh_rule_id/wazuh_rule_level or anything else the model
features on — sharing a source between label and feature is exactly the
ML-1 mistake (predicting rule_level from rule_level scores 0.9996 and proves
nothing). Keeping the two independent is what makes this number meaningful.

Scope: only sshd auth_failed/auth_success events are scored. Those are the
only events decision_policy.process_event routes through the probability
threshold (decide()) — everything else goes through the separate rule-based
_handle_non_ssh() branch, which has no probability to score.
"""
from __future__ import annotations

from demo_seed import generate_events
from config import settings
from modules import feature_extractor, inference
from modules.decision_policy import _apply_min_attempts_gate, decide
from ml.alert_features import featurize_normalized_event
from runtime import whitelist as whitelist_cache
from runtime.window_store import reset_extractor
from schemas.normalized_event import NormalizedEvent


def run_eval(n: int = 500) -> dict:
    """Replay the demo dataset through the real decision path and score it.

    Returns TPR/FPR plus the confusion-matrix counts they're built from, and
    the model version scored — enough to tell whether a number is trustworthy
    without inventing metrics the data can't support.
    """
    if inference._model is None:
        inference.load_model()

    # Fresh state per call so repeated runs (and test collection order)
    # produce the same result — reset_extractor()/reset the whitelist wipe
    # any rolling-window state a prior call left behind.
    reset_extractor()
    whitelist_cache.reset_whitelist_cache()

    rows = generate_events(n)
    t1, t2 = settings.thresholds.t1, settings.thresholds.t2

    tp = fp = tn = fn = 0
    for row in rows:
        if row["channel"] != "sshd" or row["event_type"] not in ("auth_failed", "auth_success"):
            continue

        event = NormalizedEvent(
            **{k: v for k, v in row.items() if k != "is_attack_scenario"}
        )

        # Same sequence process_event runs: update the rolling window first
        # (every sshd event does, whitelisted or not), then skip inference
        # for whitelisted traffic exactly like the product does.
        x_ssh = feature_extractor.extract_ssh_features(event)
        if whitelist_cache.is_whitelisted(event.src_ip, event.username, event.ts):
            p = 0.0
        else:
            feat = featurize_normalized_event(event)
            p = inference.infer_event(feat)["p"]
            p = _apply_min_attempts_gate(p, float(x_ssh[0]), t1)

        decision = decide(p, t1, t2)
        predicted_attack = decision != "allow"
        actual_attack = bool(row.get("is_attack_scenario"))

        if actual_attack and predicted_attack:
            tp += 1
        elif actual_attack and not predicted_attack:
            fn += 1
        elif not actual_attack and predicted_attack:
            fp += 1
        else:
            tn += 1

    events_evaluated = tp + fp + tn + fn
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "events_evaluated": events_evaluated,
        "true_positive_rate": tpr,
        "false_positive_rate": fpr,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "model_version": inference.get_model_version(),
    }


def _print_report(report: dict) -> None:
    print("LureGuard eval — sshd decision path vs demo-dataset ground truth")
    print(f"  model_version:        {report['model_version']}")
    print(f"  events_evaluated:     {report['events_evaluated']}")
    print(f"  true_positive_rate:   {report['true_positive_rate']:.3f}")
    print(f"  false_positive_rate:  {report['false_positive_rate']:.3f}")
    print(
        "  confusion matrix:     "
        f"TP={report['true_positives']} FN={report['false_negatives']} "
        f"FP={report['false_positives']} TN={report['true_negatives']}"
    )


if __name__ == "__main__":
    _print_report(run_eval())
