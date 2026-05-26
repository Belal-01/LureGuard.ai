"""Shared offline training / evaluation (real labeled data only)."""
from __future__ import annotations

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

from ml.feature_contract import FEATURE_COLUMNS


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


def train_and_evaluate(
    df: pd.DataFrame,
    seed: int,
    min_precision: float,
    beta: float,
    *,
    feature_columns: list[str] | None = None,
    n_jobs: int = 1,
) -> dict:
    cols = feature_columns or FEATURE_COLUMNS
    x = df[cols].copy()
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
        n_jobs=n_jobs,
        random_state=seed,
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    cv_scores = cross_validate(
        model,
        x_train_scaled,
        y_train,
        cv=cv,
        scoring=["roc_auc", "average_precision", "f1", "precision", "recall"],
        n_jobs=n_jobs,
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
        "feature_columns": cols,
    }
