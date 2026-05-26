"""Tutor figures: confusion matrix + validation loss vs model size."""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

ROOT = Path(__file__).resolve().parent.parent
METRICS = ROOT / "ml/models/metrics.json"
OUT = ROOT / "ml/models"


def _load_splits(seed: int = 42):
    from ml.alert_features import ALERT_FEATURE_COLUMNS
    from ml.dataset_loaders import load_true_labeled_dataset

    df = load_true_labeled_dataset(max_rows=80_000, seed=seed)
    x = df[ALERT_FEATURE_COLUMNS]
    y = df["target"].astype(int).to_numpy()

    x_trainval, x_test, y_trainval, y_test = train_test_split(
        x, y, test_size=0.20, stratify=y, random_state=seed
    )
    x_train, x_val, y_train, y_val = train_test_split(
        x_trainval, y_trainval, test_size=0.20, stratify=y_trainval, random_state=seed
    )
    scaler = MinMaxScaler()
    x_train_s = scaler.fit_transform(x_train)
    x_val_s = scaler.transform(x_val)
    x_test_s = scaler.transform(x_test)
    return x_train_s, y_train, x_val_s, y_val, x_test_s, y_test


def plot_loss_vs_trees(out: Path, seed: int = 42) -> None:
    """
    Fresh RF per tree count (no warm_start). Accuracy is easier to read than log loss
    with class_weight='balanced_subsample' (probabilities are not well calibrated).
    """
    x_train_s, y_train, x_val_s, y_val, _, _ = _load_splits(seed)

    steps = [25, 50, 75, 100, 150, 200, 300, 400, 500]
    train_acc, val_acc = [], []

    for n in steps:
        model = RandomForestClassifier(
            n_estimators=n,
            max_depth=16,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            n_jobs=1,
            random_state=seed,
        )
        model.fit(x_train_s, y_train)
        train_acc.append(model.score(x_train_s, y_train))
        val_acc.append(model.score(x_val_s, y_val))

    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.plot(steps, train_acc, "o-", color="#2563eb", lw=2, label="Train accuracy")
    ax.plot(steps, val_acc, "s-", color="#dc2626", lw=2, label="Validation accuracy")
    ax.set_xlabel("Number of trees in the forest", fontsize=11)
    ax.set_ylabel("Accuracy (higher is better)", fontsize=11)
    ax.set_title(
        "Model size vs accuracy (80k-row sample, fresh fit each point)\n"
        "More trees improve accuracy, then plateau — final model uses 500 trees",
        fontsize=11,
        fontweight="bold",
    )
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    ymin = min(min(train_acc), min(val_acc)) - 0.005
    ymax = 1.0
    ax.set_ylim(max(0.9, ymin), ymax)
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_confusion_from_metrics(out: Path) -> None:
    m = json.loads(METRICS.read_text())
    cm = m["training"]["test_tuned_threshold"]["confusion_matrix"]
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    mat = np.array([[tn, fp], [fn, tp]])

    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    im = ax.imshow(mat, cmap="Blues")
    for (i, j), v in np.ndenumerate(mat):
        ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=13, fontweight="bold")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted\nbenign", "Predicted\nattack"])
    ax.set_yticklabels(["Actual\nbenign", "Actual\nattack"])
    acc = (tn + tp) / (tn + fp + fn + tp)
    ax.set_title(
        f"Final model — hold-out test (100,000 alerts)\n"
        f"Accuracy {acc:.2%} | FP={fp:,} | FN={fn:,}",
        fontsize=12,
        fontweight="bold",
    )
    fig.colorbar(im, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    plot_loss_vs_trees(OUT / "training_loss_vs_trees.png")
    plot_confusion_from_metrics(OUT / "training_confusion_matrix.png")
    print("Wrote tutor images under ml/models/")


if __name__ == "__main__":
    main()
