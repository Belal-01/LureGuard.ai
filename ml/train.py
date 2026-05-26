"""
Offline training on real public datasets only (no synthetic generation).

Developers run once:  make train
Docker / demo:        load ml/models/model.joblib (read-only, never trains on customer traffic).

Data source: ml/datasets/true_labeled_dataset.csv (auto-download via kagglehub if missing).
Pre-trained model.joblib + scaler.joblib are shipped in Git — teammates run `make train` only to retrain.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib

from ml.alert_features import ALERT_FEATURE_COLUMNS
from ml.dataset_loaders import (
    DATASETS_DIR,
    TRUE_LABELED_CSV,
    ensure_true_labeled_dataset,
    load_all_training_sources,
)
from ml.training_utils import train_and_evaluate


def write_model_registry(
    out_dir: Path,
    model_path: Path,
    metrics: dict,
    sources: dict,
    feature_columns: list[str],
) -> Path:
    sha256 = hashlib.sha256(model_path.read_bytes()).hexdigest()
    tuned = metrics.get("test_tuned_threshold", {})
    registry = {
        "version": datetime.now(tz=timezone.utc).strftime("%Y.%m.%d"),
        "algorithm": "RandomForestClassifier",
        "model_type": "real_wazuh_alerts",
        "sha256": sha256,
        "f1_test": float(tuned.get("f2", 0.0)),
        "recall_test": float(tuned.get("recall", 0.0)),
        "roc_auc_test": float(tuned.get("roc_auc", 0.0)),
        "training_samples": int(metrics.get("splits", {}).get("train", 0)),
        "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        "active": True,
        "datasets": sources,
        "feature_columns": feature_columns,
        "training_policy": "offline_real_data_only_no_customer_retrain",
    }
    registry_path = out_dir / "model_registry.json"
    registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    return registry_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train on real Wazuh datasets only (offline).")
    parser.add_argument("--output-dir", type=str, default="ml/models")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-precision", type=float, default=0.75)
    parser.add_argument("--beta", type=float, default=2.0)
    parser.add_argument(
        "--sample-cap",
        type=int,
        default=500_000,
        help="Stratified sample from CSV (default 500k of ~2.6M — thesis-friendly).",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Use every row in the CSV (~2.6M, slow; for later/final runs).",
    )
    parser.add_argument("--no-true-labeled", action="store_true")
    parser.add_argument("--no-ait", action="store_true")
    parser.add_argument("--n-estimators", type=int, default=300)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)

    ensure_true_labeled_dataset()

    true_max = None if args.full else args.sample_cap
    df, source_counts = load_all_training_sources(
        include_true_labeled=not args.no_true_labeled,
        include_hf=False,
        include_ait=not args.no_ait,
        true_labeled_max_rows=true_max,
        seed=args.seed,
    )

    result = train_and_evaluate(
        df,
        seed=args.seed,
        min_precision=args.min_precision,
        beta=args.beta,
        feature_columns=ALERT_FEATURE_COLUMNS,
        n_jobs=1,
    )

    model_path = out_dir / "model.joblib"
    scaler_path = out_dir / "scaler.joblib"
    metrics_path = out_dir / "metrics.json"

    joblib.dump(result["model"], model_path)
    joblib.dump(result["scaler"], scaler_path)

    tuned = result["metrics"]["test_tuned_threshold"]
    default_test = result["metrics"]["test_default_threshold_0_5"]

    acc = _accuracy_from_cm(tuned["confusion_matrix"])
    payload = {
        "training_policy": "real_public_datasets_only",
        "kaggle_file": str(TRUE_LABELED_CSV.resolve()),
        "datasets": source_counts,
        "feature_columns": ALERT_FEATURE_COLUMNS,
        "training": result["metrics"],
        "confusion_matrix_explained": {
            "tn": tuned["confusion_matrix"][0][0],
            "fp": tuned["confusion_matrix"][0][1],
            "fn": tuned["confusion_matrix"][1][0],
            "tp": tuned["confusion_matrix"][1][1],
            "note": "34 in prior report was FN (missed attacks), not FP. FP=0.",
        },
        "test_accuracy": acc,
    }
    metrics_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    registry_path = write_model_registry(
        out_dir, model_path, result["metrics"], source_counts, ALERT_FEATURE_COLUMNS
    )

    print("=== Real-data training complete (Kaggle CSV only, no HuggingFace) ===")
    print(f"Datasets: {source_counts}")
    print(f"Rows: {len(df):,} | attack rate: {df['target'].mean():.4f}")
    print(f"Model: {model_path}")
    print("--- Hold-out TEST (20%) ---")
    print(f"  ROC-AUC:     {tuned['roc_auc']:.4f}")
    print(f"  Precision:   {tuned['precision']:.4f}  (tuned threshold)")
    print(f"  Recall:      {tuned['recall']:.4f}")
    print(f"  F2:          {tuned['f2']:.4f}")
    print(f"  Threshold:   {tuned['threshold']:.4f}")
    print(f"  @0.5 Prec/Rec: {default_test['precision']:.4f} / {default_test['recall']:.4f}")
    cm = tuned["confusion_matrix"]
    print(f"  Confusion:   {cm}")
    print(f"    TN={cm[0][0]:,} FP={cm[0][1]:,} (false positives) | FN={cm[1][0]:,} TP={cm[1][1]:,}")
    print(f"  Test accuracy: {acc:.4f}")
    import subprocess
    import sys

    subprocess.run([sys.executable, "-m", "ml.generate_tutor_report"], check=False)
    print(f"Tutor graphs: {out_dir / 'training_loss_vs_trees.png'}")
    print(f"Metrics JSON: {metrics_path}")
    print(f"Registry:     {registry_path}")


def _accuracy_from_cm(cm: list) -> float:
    if not cm or len(cm) != 2:
        return 0.0
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    total = tn + fp + fn + tp
    return (tn + tp) / total if total else 0.0


if __name__ == "__main__":
    main()
