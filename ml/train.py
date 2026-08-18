"""
Offline training on behavioural features (ML-1 / ML-2 / ML-12).

WHAT IT TRAINS ON
-----------------
**AIT-ADS** — Landauer, Skopik & Wurzenberger, Zenodo record 8263181,
CC-BY-4.0. 2.6M real Wazuh alerts from 8 independently built testbeds, with
ground truth published as attack-phase start/end times in `labels.csv`.
Published, citable, and containing far more variety than one lab machine can
generate.

Two properties are the whole reason ML-12 exists:

  1. **The label is a time window, never a severity.** An alert is an attack
     iff its `@timestamp` falls inside a labelled phase for its testbed. That
     is independent of `rule.level`, `rule.id` and decoder, so ML-1's leak is
     impossible *by construction* rather than avoided by discipline. See
     `ml.dataset_loaders._ait_alert_label`.

  2. **Evaluation is cross-testbed.** Six environments train, two are held out
     whole. A random row split inside one environment measures memorisation:
     every row shares its hosts, its address ranges, its benign user simulation
     and its single attacker. Holding out whole testbeds is the only honest
     generalisation number this project can produce, and it is the direct
     answer to the "52 false positives against the rule's 6" finding.

WHAT IT NO LONGER TRAINS ON, AND WHY
------------------------------------
  * `core/demo_seed.py` — scenarios we wrote ourselves: 45 web attack rows from
    2 source IPs per seed, and "benign" meant four patterns we invented. A
    model fitted on it can only recognise attacks its author already thought
    of. It still drives `make demo` and `make eval`; it no longer drives `make
    train`.
  * `ml/datasets/true_labeled_dataset.csv` — no timestamp column, so not one
    feature in ml/feature_contract.py is computable from it; 7 distinct
    rule_ids, and a pure `rule_id` lookup scores 98.36%. That is ML-1 again
    with the channel swapped. Kept as evidence, trained on by nothing.

HOW MUCH THIS NUMBER IS WORTH
-----------------------------
More than the last one, and still not a field number. What remains optimistic:
all 8 testbeds come from one 2022 capture campaign with one attack toolchain,
and the published windows label *everything* happening during a phase as
attack, including benign mail logins that overlap it. Read the held-out block
as "this transfers to a network it has never seen", not as "this is what it
will do on your VPS".
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "core") not in sys.path:
    sys.path.insert(0, str(REPO / "core"))

from ml.dataset_loaders import (  # noqa: E402
    AIT_ADS_DIR,
    ensure_ait_ads,
    iter_ait_alerts,
    load_ait_attack_windows,
)
from ml.feature_contract import FEATURE_COLUMNS  # noqa: E402
from ml.training_utils import train_and_evaluate  # noqa: E402

# ML-12: whole testbeds are held out, not rows. Training and testing inside one
# environment measures memorisation — every row of a scenario shares its hosts,
# its IP ranges, its benign user simulation and its one attacker. The split is
# by *environment* so the reported number answers "does this transfer to a
# network it has never seen", which is the only question the 52-false-positive
# finding left open. One large and one small testbed on each side, so neither
# side is only-busy or only-quiet.
AIT_TRAIN_SCENARIOS = ["fox", "harrison", "russellmitchell", "shaw", "wardbeck", "wilson"]
AIT_HELD_OUT_SCENARIOS = ["santos", "wheeler"]

# "Believe the SIEM" — the cheap rule the model has to beat to justify existing.
# Same constant and meaning as core/evaluate.py's rules_wazuh_level_ge_5.
WAZUH_LEVEL_BASELINE = 5


def build_ait_dataset(
    scenarios: list[str],
    *,
    stride: int = 1,
    directory: Path | None = None,
) -> pd.DataFrame:
    """Replay AIT-ADS testbeds through the *production* ingest path, one row per alert.

    Each alert goes `collector.normalize_event` -> `feature_extractor.
    extract_event_features` — the same two calls a live Wazuh webhook makes —
    so f1..f8 mean the same thing at fit time and at serve time. That is the
    whole reason AIT is usable where the Kaggle CSV was not: these alerts carry
    real timestamps, so a rolling window over them is a real rolling window.

    Host-local alerts are kept, not skipped. They used to be dropped because
    the shared "0.0.0.0" fallback fused every one of them into a single
    fictitious mega-source whose f1 measured the monitoring topology rather
    than anyone's behaviour. `feature_extractor._window_key` now falls back to
    the *agent*, so host-local activity stays per-host — and dropping these
    rows would discard the attacks we most want: only 28 of 158
    privilege-escalation alerts in this corpus carry a source IP at all.

    `stride` subsamples the emitted rows; the window is still updated by every
    alert, so the features of a kept row are computed from the complete history
    that preceded it. Sampling is systematic rather than stratified so the
    attack base rate of the testbed survives into the sample.
    """
    from modules.collector import normalize_event
    from modules.feature_extractor import extract_event_features, features_to_row
    from runtime import whitelist as whitelist_cache
    from runtime.window_store import reset_extractor
    from schemas.wazuh_alert import WazuhAlert

    windows = load_ait_attack_windows((directory or AIT_ADS_DIR) / "labels.csv")
    records: list[dict] = []

    for scenario in scenarios:
        # One testbed's history must not bleed into the next one's first events.
        reset_extractor()
        whitelist_cache.reset_whitelist_cache()
        kept = seen = 0

        for alert, _epoch, label in iter_ait_alerts(
            scenario, directory=directory, windows=windows
        ):
            alert["timestamp"] = alert.get("@timestamp", "")
            event = normalize_event(WazuhAlert(**alert))
            row = features_to_row(extract_event_features(event))
            seen += 1
            if seen % stride:
                continue
            kept += 1
            row["target"] = int(label)
            row["source"] = scenario
            row["channel"] = event.channel
            # Baseline only — never a feature, never a label. ML-1 is about what
            # the model *scores*, and this column is dropped before the fit.
            row["wazuh_rule_level"] = int(event.wazuh_rule_level)
            records.append(row)

        print(f"  {scenario:<16} alerts_with_src_ip={seen:>8,}  rows_kept={kept:>7,}")

    return pd.DataFrame.from_records(records)


def _rates(pairs: list[tuple[bool, bool]]) -> dict:
    """(actual, predicted) -> the same TPR/FPR shape core/evaluate.py reports."""
    tp = sum(1 for a, p in pairs if a and p)
    fn = sum(1 for a, p in pairs if a and not p)
    fp = sum(1 for a, p in pairs if not a and p)
    tn = sum(1 for a, p in pairs if not a and not p)
    return {
        "true_positive_rate": tp / (tp + fn) if (tp + fn) else 0.0,
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "events_evaluated": tp + fn + fp + tn,
    }


def evaluate_held_out(df: pd.DataFrame, model, scaler, threshold: float) -> dict:
    """Score held-out testbeds and the rule baselines the model must beat.

    `should_alert()` is deliberately not one of the baselines here: since ML-10
    it *contains* this classifier on the web path, so scoring it would be
    scoring the model against itself, and it re-enters the extractor, which
    would double-update the rolling window mid-replay.
    """
    probs = model.predict_proba(scaler.transform(df[list(FEATURE_COLUMNS)]))[:, 1]
    actual = df["target"].astype(bool).tolist()
    levels = df["wazuh_rule_level"].tolist()

    out = {
        "model": _rates([(a, p >= threshold) for a, p in zip(actual, probs, strict=True)]),
        "rules_wazuh_level_ge_5": _rates(
            [(a, lv >= WAZUH_LEVEL_BASELINE) for a, lv in zip(actual, levels, strict=True)]
        ),
        "rules_wazuh_level_ge_10": _rates(
            [(a, lv >= 10) for a, lv in zip(actual, levels, strict=True)]
        ),
    }
    web = df["channel"] == "web"
    if web.any():
        out["model_web_only"] = _rates(
            [(a, p >= threshold)
             for a, p, w in zip(actual, probs, web.tolist(), strict=True) if w]
        )
    out["per_scenario"] = {
        s: _rates([(a, p >= threshold)
                   for a, p, sc in zip(actual, probs, df["source"].tolist(), strict=True)
                   if sc == s])
        for s in sorted(df["source"].unique())
    }
    return out


def write_model_registry(
    out_dir: Path,
    model_path: Path,
    metrics: dict,
    sources: dict,
    held_out: dict,
) -> Path:
    tuned = metrics.get("test_tuned_threshold", {})
    hm = held_out.get("model", {})
    hb = held_out.get("rules_wazuh_level_ge_5", {})
    registry = {
        "version": datetime.now(tz=timezone.utc).strftime("%Y.%m.%d"),
        "algorithm": "RandomForestClassifier",
        "model_type": "behavioural_rolling_window",
        # inference.load_model() raises on a mismatch, so this must be
        # recomputed from the artifact every single time it is rewritten.
        "sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "f1_test": float(tuned.get("f2", 0.0)),
        "recall_test": float(tuned.get("recall", 0.0)),
        "roc_auc_test": float(tuned.get("roc_auc", 0.0)),
        "training_samples": int(metrics.get("splits", {}).get("train", 0)),
        "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        "active": True,
        "datasets": sources,
        # ML-12: which environments the model saw, and which it did not. A
        # generalisation claim is unreadable without both lists.
        "train_scenarios": list(AIT_TRAIN_SCENARIOS),
        "held_out_scenarios": list(AIT_HELD_OUT_SCENARIOS),
        "held_out_evaluation": held_out,
        "held_out_tpr": float(hm.get("true_positive_rate", 0.0)),
        "held_out_fpr": float(hm.get("false_positive_rate", 0.0)),
        "held_out_baseline_tpr": float(hb.get("true_positive_rate", 0.0)),
        "held_out_baseline_fpr": float(hb.get("false_positive_rate", 0.0)),
        "label_source": (
            "AIT-ADS labels.csv attack-phase windows (UTC epoch containment on "
            "@timestamp). Independent of rule level, rule id and decoder by "
            "construction — see ml.dataset_loaders._ait_alert_label."
        ),
        # ML-1: behavioural only. Nothing here is Wazuh's verdict — no
        # rule_level, no rule_id, no decoder. The exclusion is structural: the
        # model cannot score a field that is not in this list, so the leak
        # cannot return by someone re-adding a column in a hurry.
        "feature_columns": list(FEATURE_COLUMNS),
        "training_policy": "offline_published_dataset_no_customer_retrain",
        "retired_datasets": {
            "ml/datasets/true_labeled_dataset.csv": (
                "No timestamp column, 7 distinct rule_ids, and a pure rule_id "
                "lookup scores 98.36%. Behavioural features are not computable "
                "from it and any model fitted on it re-learns Wazuh's verdict."
            ),
            "core/demo_seed.py": (
                "45 web attack rows from 2 source IPs per seed, and 'benign' "
                "meant four patterns we invented. Retired from training by "
                "ML-12; still drives `make demo` and `make eval`."
            ),
        },
        "honest_caveat": (
            "Numbers are cross-testbed: trained on 6 AIT environments, scored "
            "on 2 never seen. Lower than the old 0.956 by construction — that "
            "figure came from training and evaluating on one generator. The "
            "residual optimism left is that all 8 testbeds share one attack "
            "toolchain and one 2022 capture campaign."
        ),
    }
    registry_path = out_dir / "model_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    return registry_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train on behavioural features only.")
    parser.add_argument("--output-dir", type=str, default="ml/models")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-precision", type=float, default=0.75)
    parser.add_argument("--beta", type=float, default=2.0)
    parser.add_argument(
        "--train-stride", type=int, default=8,
        help="Keep every Nth training alert (window still fed by all of them).",
    )
    parser.add_argument(
        "--max-rows-per-class", type=int, default=15_000,
        help=(
            "Cap on rows per (testbed, class) in the training set. Without it "
            "one testbed's 410k-request dirb flood is 40%% of the fit."
        ),
    )
    parser.add_argument(
        "--eval-stride", type=int, default=1,
        help="Keep every Nth held-out alert. 1 = score the whole held-out stream.",
    )
    parser.add_argument("--dataset-dir", type=str, default=str(AIT_ADS_DIR))
    # Accepted and ignored: the row-capped CSV it used to bound is retired.
    parser.add_argument("--sample-cap", type=int, default=0, help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data_dir = Path(args.dataset_dir)
    ensure_ait_ads(directory=data_dir)

    print(f"=== AIT-ADS train ({len(AIT_TRAIN_SCENARIOS)} testbeds) ===")
    df = build_ait_dataset(
        AIT_TRAIN_SCENARIOS, stride=args.train_stride, directory=data_dir
    )
    if df.empty or df["target"].nunique() < 2:
        raise SystemExit("training set has fewer than two classes — check labels.csv join")

    # One testbed's dirb flood is 410k near-identical requests. Left uncapped it
    # would be most of the fit, and "generalises across testbeds" would mean
    # "learned fox". Cap per (testbed, class); the held-out set is never capped.
    before = len(df)
    df = (
        df.sample(frac=1, random_state=args.seed)
        .groupby(["source", "target"], group_keys=False)
        .head(args.max_rows_per_class)
        .reset_index(drop=True)
    )
    print(f"  capped {before:,} -> {len(df):,} rows "
          f"(<= {args.max_rows_per_class:,} per testbed per class)")

    result = train_and_evaluate(
        df,
        seed=args.seed,
        min_precision=args.min_precision,
        beta=args.beta,
        feature_columns=list(FEATURE_COLUMNS),
        n_jobs=1,
    )

    model_path = out_dir / "model.joblib"
    scaler_path = out_dir / "scaler.joblib"
    joblib.dump(result["model"], model_path)
    joblib.dump(result["scaler"], scaler_path)

    tuned = result["metrics"]["test_tuned_threshold"]

    print(f"=== AIT-ADS held out ({len(AIT_HELD_OUT_SCENARIOS)} testbeds, never seen) ===")
    eval_df = build_ait_dataset(
        AIT_HELD_OUT_SCENARIOS, stride=args.eval_stride, directory=data_dir
    )
    held_out = evaluate_held_out(
        eval_df, result["model"], result["scaler"], tuned["threshold"]
    )

    sources = {
        "ait_ads": {
            "citation": (
                "Landauer, Skopik & Wurzenberger — AIT Alert Data Set, "
                "Zenodo record 8263181, CC-BY-4.0."
            ),
            "train_rows": int(len(df)),
            "held_out_rows": int(len(eval_df)),
            "train_attack_rate": float(df["target"].mean()),
            "held_out_attack_rate": float(eval_df["target"].mean()),
            "train_stride": int(args.train_stride),
            "eval_stride": int(args.eval_stride),
        },
        "demo_seed_scenarios": 0,
    }
    (out_dir / "metrics.json").write_text(
        json.dumps(
            {
                "training_policy": "ait_ads_published_dataset",
                "datasets": sources,
                "train_scenarios": AIT_TRAIN_SCENARIOS,
                "held_out_scenarios": AIT_HELD_OUT_SCENARIOS,
                "feature_columns": list(FEATURE_COLUMNS),
                "training": result["metrics"],
                "held_out_evaluation": held_out,
                "feature_importances": dict(
                    zip(FEATURE_COLUMNS, [float(v) for v in result["model"].feature_importances_], strict=True)
                ),
                "caveat": (
                    "`training` below is a random row split inside the 6 training "
                    "testbeds — optimistic, because rows from one attack phase "
                    "land on both sides of it. `held_out_evaluation` is the "
                    "number that counts: whole environments the model never saw."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    registry_path = write_model_registry(
        out_dir, model_path, result["metrics"], sources, held_out
    )

    print("\n=== ML-12 training complete (AIT-ADS, cross-testbed) ===")
    print(f"Train rows: {len(df):,} ({', '.join(AIT_TRAIN_SCENARIOS)}) "
          f"| attack rate {df['target'].mean():.4f}")
    print(f"Held-out rows: {len(eval_df):,} ({', '.join(AIT_HELD_OUT_SCENARIOS)}) "
          f"| attack rate {eval_df['target'].mean():.4f}")
    print(f"Threshold: {tuned['threshold']:.4f}")
    print("--- within-training-testbeds row split (optimistic, see caveat) ---")
    print(f"  ROC-AUC {tuned['roc_auc']:.4f}  Precision {tuned['precision']:.4f}  "
          f"Recall {tuned['recall']:.4f}")
    print("--- HELD-OUT TESTBEDS (the honest number) ---")
    for name in ("model", "model_web_only", "rules_wazuh_level_ge_5", "rules_wazuh_level_ge_10"):
        r = held_out.get(name)
        if r:
            print(f"  {name:<24} TPR={r['true_positive_rate']:.3f} "
                  f"FPR={r['false_positive_rate']:.3f}  TP={r['true_positives']} "
                  f"FN={r['false_negatives']} FP={r['false_positives']} TN={r['true_negatives']}")
    for scenario, r in held_out["per_scenario"].items():
        print(f"    {scenario:<22} TPR={r['true_positive_rate']:.3f} "
              f"FPR={r['false_positive_rate']:.3f}  n={r['events_evaluated']}")
    print("  Importances: " + ", ".join(
        f"{c}={v:.3f}" for c, v in zip(FEATURE_COLUMNS, result["model"].feature_importances_, strict=True)))
    print(f"Registry:  {registry_path}")


if __name__ == "__main__":
    main()
