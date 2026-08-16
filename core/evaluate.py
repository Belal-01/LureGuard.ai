"""
VER-1: evaluation harness. Replays the demo dataset through the real scoring
code and reports what it gets right, offline, no database.

WHAT MOVED, AND WHY
-------------------
The classifier used to sit on the SSH path. It no longer does: Wazuh rule 5712
already escalates on 8 failures in 120s from one source and counts distinct
users, which is the same test f1/f3 compute at the same threshold, so the model
added nothing there (ML-8 made that path rule-driven). The classifier now scores
the **web** channel, where the likelier threat to a developer's VPS lives.

So this harness reports three things side by side, because only the comparison
answers the question worth asking — not "is the model any good", but "is the
model better than the rules it costs money to run alongside":

  model_web      the classifier on web events (headline TPR/FPR)
  rules_shipping should_alert() exactly as it ships — the real baseline
  rules_level    "believe Wazuh's severity" (rule_level >= 5), the cheap rule
                 the model has to beat to justify existing
  rules_ssh      the now rule-driven SSH path, for continuity with old runs

Label source: demo_seed.generate_events()'s `is_attack_scenario` flag, set by
the generator on the rows it built as an attack. It is never derived from
wazuh_rule_id/wazuh_rule_level or anything else scored here — sharing a source
between label and feature is exactly the ML-1 mistake (predicting rule_level
from rule_level scored 0.9996 and proved nothing).

HOW MUCH ANY OF THIS PROVES
---------------------------
The model is trained on scenarios from this same generator (different seeds).
That makes every number here a **pipeline sanity check, not evidence of field
performance**: it shows the features are computed, reach the model, and move
the score. It does not show the model detects real attacks, and no amount of
running it will, because the generator only contains attacks someone already
thought of. A near-perfect score here means the leak came back, not that the
detector is good — which is what the guard in the VER-1 acceptance check is
for.
"""
from __future__ import annotations

from config import settings
from demo_seed import generate_events
from modules import inference
from modules.decision_policy import decide, should_alert
from modules.feature_extractor import extract_event_features, features_to_row
from runtime import whitelist as whitelist_cache
from runtime.window_store import reset_extractor
from schemas.normalized_event import NormalizedEvent

# Wazuh escalates repeated 4xx from one source to level 5 (rule 31151) and a
# content match to 7-10. Level 3 is a lone 400. So "level >= 5" is the whole
# of "believe the SIEM" expressed as one comparison.
WAZUH_LEVEL_BASELINE = 5


def _rates(tp: int, fn: int, fp: int, tn: int) -> dict:
    return {
        "true_positive_rate": tp / (tp + fn) if (tp + fn) else 0.0,
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "events_evaluated": tp + fn + fp + tn,
    }


def _score(pairs: list[tuple[bool, bool]]) -> dict:
    """pairs of (actual_attack, predicted_attack) -> rates."""
    tp = sum(1 for a, p in pairs if a and p)
    fn = sum(1 for a, p in pairs if a and not p)
    fp = sum(1 for a, p in pairs if not a and p)
    tn = sum(1 for a, p in pairs if not a and not p)
    return _rates(tp, fn, fp, tn)


def run_eval(n: int = 500) -> dict:
    """Replay the demo dataset through the real scoring path and score it."""
    if inference._model is None:
        inference.load_model()

    # Fresh state per call so repeated runs (and test collection order) produce
    # the same result — a rolling window left over from a prior call would
    # silently inflate f1 on the first events of this one.
    reset_extractor()
    whitelist_cache.reset_whitelist_cache()

    rows = generate_events(n)
    t1, t2 = settings.thresholds.t1, settings.thresholds.t2

    model_web: list[tuple[bool, bool]] = []
    rules_shipping: list[tuple[bool, bool]] = []
    rules_level: list[tuple[bool, bool]] = []
    rules_ssh: list[tuple[bool, bool]] = []

    for row in rows:
        actual = bool(row.get("is_attack_scenario"))
        event = NormalizedEvent(**{k: v for k, v in row.items() if k != "is_attack_scenario"})

        # Every event with a source updates the rolling window, in timestamp
        # order, exactly as the live path does — including the ones we do not
        # score, because they are part of the history that shapes f1..f8.
        if row["channel"] not in ("sshd", "web") or not row.get("src_ip"):
            continue
        x = extract_event_features(event)

        if row["channel"] == "web":
            p = inference.infer_event(features_to_row(x))["p"]
            model_web.append((actual, decide(p, t1, t2) != "allow"))
            rules_shipping.append((actual, should_alert(event)))
            rules_level.append((actual, event.wazuh_rule_level >= WAZUH_LEVEL_BASELINE))
        elif row["event_type"] in ("auth_failed", "auth_success"):
            # ML-8: SSH is rule-driven now. Score the rule, not a probability.
            confirmed = (
                event.wazuh_rule_level >= 10
                or int(x[0]) >= settings.min_attempts_for_alert
            )
            rules_ssh.append((actual, confirmed and not whitelist_cache.is_whitelisted(
                event.src_ip, event.username, event.ts)))

    web = _score(model_web)
    report = {
        # Headline = the channel the classifier now owns.
        **web,
        "model_version": inference.get_model_version(),
        "scored_channel": "web",
        "baselines": {
            "rules_shipping": _score(rules_shipping),
            "rules_wazuh_level_ge_5": _score(rules_level),
            "rules_ssh": _score(rules_ssh),
        },
        "caveat": (
            "Trained and evaluated on the same generator (different seeds). A "
            "pipeline sanity check, not evidence of field performance."
        ),
    }
    return report


def _line(name: str, r: dict) -> str:
    return (
        f"  {name:<24} TPR={r['true_positive_rate']:.3f} FPR={r['false_positive_rate']:.3f}  "
        f"TP={r['true_positives']} FN={r['false_negatives']} "
        f"FP={r['false_positives']} TN={r['true_negatives']}"
    )


def _print_report(report: dict) -> None:
    print("LureGuard eval — demo-dataset ground truth (generator-labelled)")
    print(f"  model_version:        {report['model_version']}")
    print(f"  scored_channel:       {report['scored_channel']}")
    print(f"  events_evaluated:     {report['events_evaluated']}")
    print()
    print(_line("model (web)", report))
    for name, r in report["baselines"].items():
        print(_line(name, r))
    print()
    print(f"  NOTE: {report['caveat']}")


if __name__ == "__main__":
    _print_report(run_eval())
