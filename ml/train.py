"""
Offline training on behavioural features (ML-1 / ML-2).

WHAT THIS NO LONGER TRAINS ON, AND WHY
--------------------------------------
`ml/datasets/true_labeled_dataset.csv` (2.6M rows) is **retired from
training**. It cannot support a model:

  * its columns are `rule_level, rule_id, decoder_name, src_ip, attack_label`
    — there is **no timestamp**, so not one behavioural feature in
    ml/feature_contract.py can be computed from it;
  * the web corpus contains **7 distinct rule_ids**, and a pure `rule_id`
    lookup table scores **98.36%** on it (rule 31101 alone is 1.57M rows,
    98.4% `dirb`);
  * **94%** of source IPs carry exactly one label, so any per-IP aggregate
    memorises the IP rather than the behaviour.

A model fitted on those columns is a seven-entry lookup table wearing a
model's clothes. That is exactly ML-1 — predicting Wazuh's verdict from
Wazuh's verdict and reporting 0.9996 precision — with the channel swapped.
The file stays in the repo as the evidence for that finding; nothing trains
on it.

WHAT IT TRAINS ON INSTEAD
-------------------------
Scenarios from `core/demo_seed.py`, which are deterministic, labelled, and
carry **real timestamps**, so the rolling-window features are computable. The
labels come from the generator's `is_attack_scenario` flag, which is never
derived from any field the model sees.

HOW MUCH THIS NUMBER IS WORTH
-----------------------------
Not much, and the honest framing matters more than the digits. Training on a
generator and evaluating on the same generator is a **pipeline sanity check,
not evidence of field performance**. Held-out seeds change the source IPs and
the benign noise, but every attack scenario keeps the same hard-coded timing
(the sweep is always 3s apart, the burst always 8s), so a held-out seed is a
much weaker test than it sounds. Read `make eval` as "the wiring works and the
features move the score", never as "this is how well it detects attacks".
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

from ml.feature_contract import FEATURE_COLUMNS  # noqa: E402
from ml.training_utils import train_and_evaluate  # noqa: E402

# Seed 1337 is demo_seed.SEED — what `make eval` scores. Never train on it.
EVAL_SEED = 1337
TRAIN_SEEDS = [11, 23, 47, 59, 71, 83, 97, 109, 127, 139, 151, 163]


def build_dataset(seeds: list[int], n: int = 500) -> pd.DataFrame:
    """Replay generated scenarios through the real extractor, one row per event.

    Uses `modules.feature_extractor` — the same code path that runs in
    production — rather than a training-only reimplementation, so a feature
    can't mean one thing at fit time and another at serve time.
    """
    from demo_seed import generate_events
    from modules.feature_extractor import extract_event_features, features_to_row
    from runtime import whitelist as whitelist_cache
    from runtime.window_store import reset_extractor
    from schemas.normalized_event import NormalizedEvent

    records: list[dict] = []
    for seed in seeds:
        # Fresh rolling window per seed: one scenario's history must not leak
        # into the next seed's first events.
        reset_extractor()
        whitelist_cache.reset_whitelist_cache()

        for row in generate_events(n, seed=seed):
            # Only channels with a source and a request stream have behaviour
            # to measure. syscheck/rootcheck/cowrie are per-host state changes,
            # not per-source rates — f1..f8 are meaningless on them.
            if row["channel"] not in ("sshd", "web") or not row.get("src_ip"):
                continue
            event = NormalizedEvent(
                **{k: v for k, v in row.items() if k != "is_attack_scenario"}
            )
            x = extract_event_features(event)
            record = features_to_row(x)
            record["target"] = int(bool(row.get("is_attack_scenario")))
            record["source"] = f"demo_seed:{seed}:{row['channel']}"
            records.append(record)

    return pd.DataFrame.from_records(records)


def write_model_registry(
    out_dir: Path, model_path: Path, metrics: dict, sources: dict
) -> Path:
    tuned = metrics.get("test_tuned_threshold", {})
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
        # ML-1: behavioural only. Nothing here is Wazuh's verdict — no
        # rule_level, no rule_id, no decoder. The exclusion is structural: the
        # model cannot score a field that is not in this list, so the leak
        # cannot return by someone re-adding a column in a hurry.
        "feature_columns": list(FEATURE_COLUMNS),
        "training_policy": "offline_generated_scenarios_no_customer_retrain",
        "retired_datasets": {
            "ml/datasets/true_labeled_dataset.csv": (
                "No timestamp column, 7 distinct rule_ids, and a pure rule_id "
                "lookup scores 98.36%. Behavioural features are not computable "
                "from it and any model fitted on it re-learns Wazuh's verdict."
            )
        },
        "honest_caveat": (
            "Trained and evaluated on the same generator. Held-out seeds vary "
            "source IPs and benign noise but not attack timing. These numbers "
            "are a pipeline sanity check, not evidence of field performance."
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
    parser.add_argument("--events-per-seed", type=int, default=500)
    # Accepted and ignored: the row-capped CSV it used to bound is retired.
    parser.add_argument("--sample-cap", type=int, default=0, help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = build_dataset(TRAIN_SEEDS, n=args.events_per_seed)
    if df.empty or df["target"].nunique() < 2:
        raise SystemExit("training set has fewer than two classes — check demo_seed labels")

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

    sources = {
        "demo_seed_scenarios": int(len(df)),
        "train_seeds": TRAIN_SEEDS,
        "eval_seed_excluded": EVAL_SEED,
    }
    tuned = result["metrics"]["test_tuned_threshold"]
    (out_dir / "metrics.json").write_text(
        json.dumps(
            {
                "training_policy": "generated_scenarios_only",
                "datasets": sources,
                "feature_columns": list(FEATURE_COLUMNS),
                "training": result["metrics"],
                "feature_importances": dict(
                    zip(FEATURE_COLUMNS, [float(v) for v in result["model"].feature_importances_], strict=True)
                ),
                "caveat": (
                    "Within-generator metrics. The split below is a random row "
                    "split, so rows from one scenario appear in both train and "
                    "test — treat these as optimistic and read `make eval` "
                    "(seed 1337, never trained on) as the held-out number."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    registry_path = write_model_registry(out_dir, model_path, result["metrics"], sources)

    print("=== Behavioural training complete (generated scenarios only) ===")
    print(f"Rows: {len(df):,} | attack rate: {df['target'].mean():.4f}")
    print(f"Features: {list(FEATURE_COLUMNS)}")
    print("--- within-generator hold-out (optimistic, see caveat) ---")
    print(f"  ROC-AUC:   {tuned['roc_auc']:.4f}")
    print(f"  Precision: {tuned['precision']:.4f}   Recall: {tuned['recall']:.4f}")
    print(f"  Confusion: {tuned['confusion_matrix']}")
    print("  Importances: " + ", ".join(
        f"{c}={v:.3f}" for c, v in zip(FEATURE_COLUMNS, result["model"].feature_importances_, strict=True)))
    print(f"Registry:  {registry_path}")
    print("Run `make eval` for the held-out (seed 1337) number that actually counts.")


if __name__ == "__main__":
    main()
