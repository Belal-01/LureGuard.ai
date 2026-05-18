from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    fbeta_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.preprocessing import MinMaxScaler

from feature_contract import FEATURE_COLUMNS, FEATURE_DRIFT_COLUMNS, feature_contract_rows
from LureGuardExtractor import LureGuardExtractor


def _clip(a: np.ndarray | float, lo: float, hi: float):
    return np.clip(a, lo, hi)


def _make_ips(prefix_a: int, prefix_b: int, count: int) -> list[str]:
    return [f"10.{prefix_a}.{prefix_b}.{i}" for i in range(1, count + 1)]


def generate_dataset(
    n_samples: int = 60000,
    attack_ratio: float = 0.08,
    label_noise: float = 0.01,
    seed: int = 42,
) -> pd.DataFrame:
    if not (0.001 <= attack_ratio <= 0.50):
        raise ValueError("attack_ratio must be between 0.001 and 0.50")
    if not (0.0 <= label_noise <= 0.20):
        raise ValueError("label_noise must be between 0.0 and 0.20")

    rng = np.random.default_rng(seed)
    extractor = LureGuardExtractor(
        window_seconds=300,
        burst_subwindow_seconds=10,
        baseline_min_count=30,
        baseline_store_path=None,
    )

    benign_ips = _make_ips(10, 10, 350)
    attack_ips = _make_ips(10, 20, 120)
    all_ips = benign_ips + attack_ips

    ip_last_ts = {ip: datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp() for ip in all_ips}
    ip_benign_users = {
        ip: [f"user{idx % 3}", f"svc{idx % 2}"]
        for idx, ip in enumerate(benign_ips)
    }

    common_attack_users = [
        "root",
        "admin",
        "oracle",
        "postgres",
        "backup",
        "git",
        "devops",
        "test",
    ]

    rows = []

    for _ in range(n_samples):
        is_attack = 1 if rng.random() < attack_ratio else 0

        if is_attack:
            profile = rng.choice(["brute", "lowslow", "spray"], p=[0.60, 0.25, 0.15])
            src_ip = rng.choice(attack_ips if rng.random() < 0.85 else benign_ips)

            if profile == "brute":
                delta = float(_clip(rng.lognormal(mean=1.1, sigma=0.75), 0.2, 20.0))
                status = "failed" if rng.random() < 0.95 else "success"
                username = rng.choice(common_attack_users)
            elif profile == "lowslow":
                delta = float(_clip(rng.lognormal(mean=5.0, sigma=0.75), 20.0, 1800.0))
                status = "failed" if rng.random() < 0.80 else "success"
                username = rng.choice(common_attack_users[:5])
            else:
                delta = float(_clip(rng.lognormal(mean=2.6, sigma=0.9), 2.0, 180.0))
                status = "failed" if rng.random() < 0.90 else "success"
                username = f"user{int(rng.integers(1, 250))}"

            is_whitelist = bool(rng.random() < 0.02)
        else:
            src_ip = rng.choice(benign_ips)
            delta = float(_clip(rng.lognormal(mean=5.7, sigma=0.85), 30.0, 2600.0))
            status = "failed" if rng.random() < 0.12 else "success"
            username = rng.choice(ip_benign_users[src_ip])
            is_whitelist = bool(rng.random() < 0.20)

        event_ts = ip_last_ts[src_ip] + delta
        ip_last_ts[src_ip] = event_ts
        event_iso = datetime.fromtimestamp(event_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")

        features = extractor.update_from_raw(
            src_ip=src_ip,
            username=str(username),
            status=status,
            event_timestamp=event_iso,
            is_whitelist=is_whitelist,
        )

        rows.append(features + [is_attack])

    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["target"])

    n_flip = int(len(df) * label_noise)
    if n_flip > 0:
        flip_idx = rng.choice(df.index, size=n_flip, replace=False)
        df.loc[flip_idx, "target"] = 1 - df.loc[flip_idx, "target"]

    return df


def find_threshold(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    beta: float = 2.0,
    min_precision: float = 0.75,
) -> dict:
    precision, recall, thresholds = precision_recall_curve(y_true, y_prob)
    aligned_thresholds = np.r_[thresholds, 1.0]
    f_beta = (1 + beta**2) * (precision * recall) / ((beta**2 * precision) + recall + 1e-12)

    valid = np.where(precision >= min_precision)[0]
    if valid.size > 0:
        best_idx = valid[np.argmax(f_beta[valid])]
    else:
        best_idx = int(np.argmax(f_beta))

    best_threshold = float(aligned_thresholds[best_idx])
    return {
        "threshold": best_threshold,
        "precision": float(precision[best_idx]),
        "recall": float(recall[best_idx]),
        "f_beta": float(f_beta[best_idx]),
    }


def train_and_evaluate(df: pd.DataFrame, seed: int, min_precision: float, beta: float) -> dict:
    x = df[FEATURE_COLUMNS].copy()
    y = df["target"].astype(int).to_numpy()

    x_trainval, x_test, y_trainval, y_test = train_test_split(
        x, y, test_size=0.20, stratify=y, random_state=seed
    )
    x_train, x_val, y_train, y_val = train_test_split(
        x_trainval, y_trainval, test_size=0.20, stratify=y_trainval, random_state=seed
    )

    scaler = MinMaxScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_val_scaled = scaler.transform(x_val)
    x_test_scaled = scaler.transform(x_test)

    model = RandomForestClassifier(
        n_estimators=500,
        max_depth=18,
        min_samples_split=8,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        bootstrap=True,
        n_jobs=-1,
        random_state=seed,
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    cv_scores = cross_validate(
        model,
        x_train_scaled,
        y_train,
        cv=cv,
        scoring=["roc_auc", "average_precision", "f1", "precision", "recall"],
        n_jobs=-1,
    )

    model.fit(x_train_scaled, y_train)

    val_probs = model.predict_proba(x_val_scaled)[:, 1]
    threshold_info = find_threshold(y_val, val_probs, beta=beta, min_precision=min_precision)
    threshold = threshold_info["threshold"]

    test_probs = model.predict_proba(x_test_scaled)[:, 1]
    y_pred_default = (test_probs >= 0.5).astype(int)
    y_pred_tuned = (test_probs >= threshold).astype(int)

    report_tuned = classification_report(y_test, y_pred_tuned, digits=4)

    metrics = {
        "cv_mean": {
            "roc_auc": float(np.mean(cv_scores["test_roc_auc"])),
            "average_precision": float(np.mean(cv_scores["test_average_precision"])),
            "f1": float(np.mean(cv_scores["test_f1"])),
            "precision": float(np.mean(cv_scores["test_precision"])),
            "recall": float(np.mean(cv_scores["test_recall"])),
        },
        "cv_std": {
            "roc_auc": float(np.std(cv_scores["test_roc_auc"])),
            "average_precision": float(np.std(cv_scores["test_average_precision"])),
            "f1": float(np.std(cv_scores["test_f1"])),
            "precision": float(np.std(cv_scores["test_precision"])),
            "recall": float(np.std(cv_scores["test_recall"])),
        },
        "threshold_selection": threshold_info,
        "test_default_threshold_0_5": {
            "roc_auc": float(roc_auc_score(y_test, test_probs)),
            "average_precision": float(average_precision_score(y_test, test_probs)),
            "precision": float(precision_score(y_test, y_pred_default, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred_default, zero_division=0)),
            "f2": float(fbeta_score(y_test, y_pred_default, beta=2.0, zero_division=0)),
            "confusion_matrix": confusion_matrix(y_test, y_pred_default).tolist(),
        },
        "test_tuned_threshold": {
            "threshold": float(threshold),
            "roc_auc": float(roc_auc_score(y_test, test_probs)),
            "average_precision": float(average_precision_score(y_test, test_probs)),
            "precision": float(precision_score(y_test, y_pred_tuned, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred_tuned, zero_division=0)),
            "f2": float(fbeta_score(y_test, y_pred_tuned, beta=2.0, zero_division=0)),
            "confusion_matrix": confusion_matrix(y_test, y_pred_tuned).tolist(),
            "classification_report": report_tuned,
        },
        "splits": {
            "train": int(len(x_train)),
            "validation": int(len(x_val)),
            "test": int(len(x_test)),
        },
    }

    return {
        "model": model,
        "scaler": scaler,
        "metrics": metrics,
    }


def _safe_edges(values: np.ndarray, n_bins: int = 10) -> list[float]:
    unique_vals = np.unique(values.astype(float))
    unique_vals.sort()

    if len(unique_vals) == 1:
        center = float(unique_vals[0])
        return [center - 0.5, center + 0.5]

    if len(unique_vals) <= n_bins:
        mids = (unique_vals[:-1] + unique_vals[1:]) / 2.0
        edges = [unique_vals[0] - 1e-6] + mids.tolist() + [unique_vals[-1] + 1e-6]
        return [float(x) for x in edges]

    quantiles = np.linspace(0.0, 1.0, n_bins + 1)
    edges = np.quantile(values, quantiles)
    for i in range(1, len(edges)):
        if edges[i] <= edges[i - 1]:
            edges[i] = edges[i - 1] + 1e-6
    return [float(x) for x in edges]


def build_drift_baseline(df: pd.DataFrame) -> dict:
    payload = {"features": {}}

    for feature in FEATURE_DRIFT_COLUMNS:
        series = df[feature].astype(float).to_numpy()
        if feature == "f8":
            edges = [-0.5, 0.5, 1.5]
        else:
            edges = _safe_edges(series, n_bins=10)

        hist, _ = np.histogram(series, bins=np.array(edges, dtype=float))
        expected = (hist / max(hist.sum(), 1)).astype(float).tolist()

        payload["features"][feature] = {
            "bin_edges": [float(x) for x in edges],
            "expected": expected,
            "mean": float(np.mean(series)),
            "std": float(np.std(series)),
        }

    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train intrusion classifier with train/serve feature parity.")
    parser.add_argument("--n-samples", type=int, default=60000, help="Total synthetic events.")
    parser.add_argument("--attack-ratio", type=float, default=0.08, help="Attack class ratio.")
    parser.add_argument("--label-noise", type=float, default=0.01, help="Label flip ratio.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    parser.add_argument(
        "--output-dir",
        type=str,
        default="artifacts",
        help="Directory to save model, scaler, metrics, and drift baseline.",
    )
    parser.add_argument(
        "--min-precision",
        type=float,
        default=0.75,
        help="Minimum precision target for threshold selection.",
    )
    parser.add_argument(
        "--beta",
        type=float,
        default=2.0,
        help="Beta for F-beta optimization when selecting threshold.",
    )
    parser.add_argument(
        "--save-dataset",
        action="store_true",
        help="Save generated training dataset as CSV in output directory.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = generate_dataset(
        n_samples=args.n_samples,
        attack_ratio=args.attack_ratio,
        label_noise=args.label_noise,
        seed=args.seed,
    )

    result = train_and_evaluate(df, seed=args.seed, min_precision=args.min_precision, beta=args.beta)

    model_path = out_dir / "model.joblib"
    scaler_path = out_dir / "scaler.joblib"
    metrics_path = out_dir / "metrics.json"
    drift_baseline_path = out_dir / "drift_baseline.json"

    joblib.dump(result["model"], model_path)
    joblib.dump(result["scaler"], scaler_path)

    payload = {
        "dataset": {
            "rows": int(len(df)),
            "attack_ratio_actual": float(df["target"].mean()),
            "feature_columns": FEATURE_COLUMNS,
            "feature_contract": feature_contract_rows(),
        },
        "training": result["metrics"],
        "parity": {
            "extractor": "LureGuardExtractor.update_from_raw",
            "status": "train_and_serve_use_same_extractor",
        },
    }

    metrics_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    drift_baseline = build_drift_baseline(df)
    drift_baseline_path.write_text(json.dumps(drift_baseline, indent=2), encoding="utf-8")

    if args.save_dataset:
        dataset_path = out_dir / "synthetic_dataset.csv"
        df.to_csv(dataset_path, index=False)

    print(f"Dataset rows: {len(df):,}")
    print(f"Actual attack ratio: {df['target'].mean():.4f}")
    print(f"Model saved: {model_path}")
    print(f"Scaler saved: {scaler_path}")
    print(f"Metrics saved: {metrics_path}")
    print(f"Drift baseline saved: {drift_baseline_path}")
    print(f"Tuned threshold: {result['metrics']['test_tuned_threshold']['threshold']:.4f}")
    print(
        "Test tuned precision/recall: "
        f"{result['metrics']['test_tuned_threshold']['precision']:.4f}/"
        f"{result['metrics']['test_tuned_threshold']['recall']:.4f}"
    )


if __name__ == "__main__":
    main()
