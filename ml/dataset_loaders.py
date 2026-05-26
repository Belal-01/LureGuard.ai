"""
Load and merge Wazuh alert datasets for offline alert-triage training.

Primary source: Kaggle `minahilsiddiq/wazuh-labeled-alert-features` (auto via kagglehub).
Production artifacts: `ml/models/model.joblib` + `scaler.joblib` (shipped in Git).

Sources (under ml/datasets/):
  - true_labeled_dataset.csv  (Kaggle — downloaded by code if missing)
  - hf-wazuh-alerts.json      (optional Hugging Face cache)
  - optional extra *.csv under ml/datasets/extra/
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from ml.alert_features import (
    ALERT_FEATURE_COLUMNS,
    detect_label_column,
    featurize_wazuh_alert,
    kaggle_row_to_features,
    normalize_label,
    parse_alert_json,
    rows_to_frame,
    true_labeled_row_to_features,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
DATASETS_DIR = _REPO_ROOT / "ml" / "datasets"
TRUE_LABELED_CSV = DATASETS_DIR / "true_labeled_dataset.csv"
KAGGLEHUB_DATASET_ID = "minahilsiddiq/wazuh-labeled-alert-features"
HF_CACHE_JSON = DATASETS_DIR / "hf-wazuh-alerts.json"
HF_FIRST_ROWS_URL = (
    "https://datasets-server.huggingface.co/first-rows"
    "?dataset=kholil-lil%2Fwazuh-alerts&config=default&split=train"
)
HF_DATASET_ID = "kholil-lil/wazuh-alerts"
AIT_ADS_DIR = DATASETS_DIR / "ait-ads"
# Zenodo: https://zenodo.org/record/8263181 — unzip under ml/datasets/ait-ads/


def download_true_labeled_dataset(
    dest: Path | None = None,
    *,
    force: bool = False,
) -> Path:
    """
    Download the Kaggle CSV via kagglehub into ml/datasets/true_labeled_dataset.csv.

    Requires: pip install -e '.[train]' (kagglehub). First run may prompt Kaggle login.
    """
    import shutil

    out = dest or TRUE_LABELED_CSV
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.is_file() and not force:
        return out

    try:
        import kagglehub
    except ImportError as exc:
        raise ImportError(
            "kagglehub is required to download training data. "
            "Run: pip install -e '.[train]'"
        ) from exc

    print(f"Downloading Kaggle dataset {KAGGLEHUB_DATASET_ID} …")
    cache_dir = Path(kagglehub.dataset_download(KAGGLEHUB_DATASET_ID))
    csv_files = sorted(cache_dir.rglob("*.csv"), key=lambda p: p.stat().st_size, reverse=True)
    if not csv_files:
        raise FileNotFoundError(f"No .csv files under Kaggle cache: {cache_dir}")

    src = csv_files[0]
    if out.exists():
        out.unlink()
    shutil.copy2(src, out)
    print(f"Dataset ready: {out} ({out.stat().st_size / (1024 * 1024):.1f} MB)")
    return out


def ensure_true_labeled_dataset(*, force_download: bool = False) -> Path:
    """Return path to labeled CSV, downloading from Kaggle when missing."""
    if TRUE_LABELED_CSV.is_file() and not force_download:
        return TRUE_LABELED_CSV
    return download_true_labeled_dataset(force=force_download)


def _iter_csv_files(directory: Path) -> Iterable[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        p for p in directory.rglob("*.csv") if p.name != TRUE_LABELED_CSV.name
    )


def fetch_hf_wazuh_alerts_cache(
    dest: Path | None = None,
    *,
    force: bool = False,
) -> Path:
    """Download HF first-rows JSON once (optional; not used by default training)."""
    import urllib.request

    out = dest or HF_CACHE_JSON
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists() and not force:
        return out
    with urllib.request.urlopen(HF_FIRST_ROWS_URL, timeout=120) as resp:
        out.write_bytes(resp.read())
    return out


def load_true_labeled_dataset(
    csv_path: Path | None = None,
    *,
    max_rows: int | None = 200_000,
    seed: int = 42,
    chunksize: int = 100_000,
) -> pd.DataFrame:
    """
    Load true_labeled_dataset.csv (rule_level, rule_id, decoder_name, src_ip, attack_label).

    attack_label == Normal → 0; any other value (dirb, wpscan, …) → 1.
    When max_rows is set, stratified reservoir sample across chunks (for multi-million rows).
    """
    path = csv_path or TRUE_LABELED_CSV
    if not path.is_file():
        path = ensure_true_labeled_dataset()

    if max_rows is None:
        reservoir: list[dict[str, float]] = []
        labels: list[int] = []
        sources: list[str] = []
        for chunk in pd.read_csv(path, chunksize=chunksize):
            for _, row in chunk.iterrows():
                label = normalize_label(row.get("attack_label"))
                if label is None:
                    continue
                reservoir.append(true_labeled_row_to_features(row))
                labels.append(label)
                sources.append("true_labeled")
        return rows_to_frame(reservoir, labels, sources)

    # Read a prefix of the file, then stratified sample (file can be 2M+ rows).
    read_cap = max(max_rows * 3, 300_000)
    parts: list[pd.DataFrame] = []
    total = 0
    for chunk in pd.read_csv(path, chunksize=chunksize):
        parts.append(chunk)
        total += len(chunk)
        if total >= read_cap:
            break

    raw = pd.concat(parts, ignore_index=True)
    raw["_target"] = raw["attack_label"].map(
        lambda v: normalize_label(v) if normalize_label(v) is not None else np.nan
    )
    raw = raw.dropna(subset=["_target"])
    raw["_target"] = raw["_target"].astype(int)

    half = max_rows // 2
    frames: list[pd.DataFrame] = []
    for cls in (0, 1):
        subset = raw[raw["_target"] == cls]
        n = min(half, len(subset))
        if n > 0:
            frames.append(subset.sample(n=n, random_state=seed))

    sampled = pd.concat(frames, ignore_index=True)
    rows = [true_labeled_row_to_features(row) for _, row in sampled.iterrows()]
    labels = sampled["_target"].astype(int).tolist()
    return rows_to_frame(rows, labels, ["true_labeled"] * len(rows))


def load_labeled_csv_dir(
    directory: Path,
    *,
    max_rows: int | None = None,
    source_name: str = "labeled_csv",
) -> pd.DataFrame:
    files = list(_iter_csv_files(directory))
    if not files:
        return pd.DataFrame(columns=[*ALERT_FEATURE_COLUMNS, "target", "source"])

    parts: list[pd.DataFrame] = []
    for path in files:
        chunk = pd.read_csv(path, nrows=max_rows)
        label_col = detect_label_column(chunk)
        if label_col is None:
            continue
        rows: list[dict[str, float]] = []
        labels: list[int] = []
        for _, series in chunk.iterrows():
            label = normalize_label(series[label_col])
            if label is None:
                continue
            if "decoder_name" in chunk.columns and "attack_label" in chunk.columns:
                rows.append(true_labeled_row_to_features(series))
            else:
                rows.append(kaggle_row_to_features(series))
            labels.append(label)
        if rows:
            frame = rows_to_frame(rows, labels, [source_name] * len(rows))
            frame["source_file"] = path.name
            parts.append(frame)

    if not parts:
        return pd.DataFrame(columns=[*ALERT_FEATURE_COLUMNS, "target", "source"])
    return pd.concat(parts, ignore_index=True)


def load_hf_wazuh_alerts(
    *,
    cache_path: Path | None = None,
    max_rows: int | None = None,
    use_datasets_library: bool = True,
) -> pd.DataFrame:
    """Load kholil-lil/wazuh-alerts (TP/FP) into ALERT_FEATURE_COLUMNS."""
    rows: list[dict[str, float]] = []
    labels: list[int] = []
    sources: list[str] = []

    if use_datasets_library:
        try:
            from datasets import load_dataset  # type: ignore[import-untyped]
        except ImportError:
            use_datasets_library = False
        else:
            ds = load_dataset(HF_DATASET_ID, split="train")
            limit = len(ds) if max_rows is None else min(max_rows, len(ds))
            for i in range(limit):
                item = ds[i]
                alert = parse_alert_json(item["input"])
                label = normalize_label(item.get("output"))
                if label is None:
                    continue
                rows.append(featurize_wazuh_alert(alert))
                labels.append(label)
                sources.append("hf_wazuh_alerts")
            return rows_to_frame(rows, labels, sources)

    cache = cache_path or HF_CACHE_JSON
    if not cache.is_file():
        fetch_hf_wazuh_alerts_cache(cache)

    payload = json.loads(cache.read_text(encoding="utf-8"))
    hf_rows = payload.get("rows", [])
    limit = len(hf_rows) if max_rows is None else min(max_rows, len(hf_rows))

    for entry in hf_rows[:limit]:
        item = entry.get("row") or {}
        alert = parse_alert_json(item["input"])
        label = normalize_label(item.get("output"))
        if label is None:
            continue
        rows.append(featurize_wazuh_alert(alert))
        labels.append(label)
        sources.append("hf_wazuh_alerts")

    if not rows:
        raise ValueError("No labeled rows in Hugging Face wazuh-alerts cache")

    return rows_to_frame(rows, labels, sources)


def _load_ait_alert_file(path: Path) -> list[tuple[dict[str, float], int]]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    parsed: object
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        rows: list[tuple[dict[str, float], int]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(alert, dict):
                label = _ait_alert_label(alert)
                if label is not None:
                    rows.append((featurize_wazuh_alert(alert), label))
        return rows

    alerts = parsed if isinstance(parsed, list) else [parsed]
    out: list[tuple[dict[str, float], int]] = []
    if isinstance(alerts, list):
        for alert in alerts:
            if isinstance(alert, dict):
                label = _ait_alert_label(alert)
                if label is not None:
                    out.append((featurize_wazuh_alert(alert), label))
    return out


def _ait_alert_label(alert: dict) -> int | None:
    """AIT-ADS: use attack_labels / ground truth when present, else Wazuh level heuristic."""
    for key in ("attack", "is_attack", "malicious", "label"):
        if key in alert:
            return normalize_label(alert[key])
    labels = alert.get("attack_labels") or alert.get("labels")
    if isinstance(labels, list) and labels:
        return 1
    level = (alert.get("rule") or {}).get("level") if isinstance(alert.get("rule"), dict) else None
    try:
        if level is not None and int(level) >= 10:
            return 1
    except (TypeError, ValueError):
        pass
    return 0


def load_ait_ads_alerts(
    directory: Path | None = None,
    *,
    max_files: int | None = 500,
) -> pd.DataFrame:
    """Load Wazuh JSON alerts from AIT-ADS (after unzip to ml/datasets/ait-ads/)."""
    root = directory or AIT_ADS_DIR
    if not root.is_dir():
        return pd.DataFrame(columns=[*ALERT_FEATURE_COLUMNS, "target", "source"])

    files = sorted(root.rglob("*.json"))
    if max_files is not None:
        files = files[:max_files]

    rows: list[dict[str, float]] = []
    labels: list[int] = []
    for path in files:
        for feats, label in _load_ait_alert_file(path):
            rows.append(feats)
            labels.append(label)

    if not rows:
        return pd.DataFrame(columns=[*ALERT_FEATURE_COLUMNS, "target", "source"])
    return rows_to_frame(rows, labels, ["ait_ads"] * len(rows))


def combine_datasets(
    frames: list[pd.DataFrame],
    *,
    dedupe: bool = True,
) -> pd.DataFrame:
    valid = [f for f in frames if f is not None and len(f) > 0]
    if not valid:
        raise ValueError("No dataset frames to combine")

    combined = pd.concat(valid, ignore_index=True)
    if dedupe:
        key_cols = ALERT_FEATURE_COLUMNS + ["target"]
        combined = combined.drop_duplicates(subset=key_cols, keep="first")
    return combined.reset_index(drop=True)


def load_all_training_sources(
    *,
    include_true_labeled: bool = True,
    include_hf: bool = False,
    include_extra_csv: bool = True,
    include_ait: bool = True,
    true_labeled_max_rows: int | None = 200_000,
    hf_max_rows: int | None = None,
    ait_max_files: int | None = 500,
    seed: int = 42,
) -> tuple[pd.DataFrame, dict[str, int]]:
    """Merge real public datasets for offline training (never customer/demo traffic)."""
    frames: list[pd.DataFrame] = []
    counts: dict[str, int] = {}

    if include_true_labeled:
        true_df = load_true_labeled_dataset(max_rows=true_labeled_max_rows, seed=seed)
        counts["kaggle_true_labeled"] = len(true_df)
        frames.append(true_df)

    if include_hf:
        try:
            hf_df = load_hf_wazuh_alerts(max_rows=hf_max_rows)
            counts["hf_wazuh_alerts"] = len(hf_df)
            frames.append(hf_df)
        except Exception as exc:
            counts["hf_wazuh_alerts"] = 0
            counts["hf_error"] = str(exc)[:200]

    if include_ait:
        ait_df = load_ait_ads_alerts(max_files=ait_max_files)
        counts["ait_ads"] = len(ait_df)
        if len(ait_df) > 0:
            frames.append(ait_df)

    if include_extra_csv:
        extra_df = load_labeled_csv_dir(DATASETS_DIR / "extra", source_name="extra_csv")
        counts["extra_csv"] = len(extra_df)
        if len(extra_df) > 0:
            frames.append(extra_df)

    if not frames:
        raise FileNotFoundError(
            f"No training data. Run: make fetch-dataset  (or  python -m ml.train  to auto-download)"
        )

    combined = combine_datasets(frames, dedupe=False)
    counts["combined_rows"] = len(combined)
    return combined, counts
