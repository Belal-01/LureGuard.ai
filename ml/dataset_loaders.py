"""
Load Wazuh alert datasets for offline training.

ML-12 — the source that actually trains the shipped model is **AIT-ADS**
(Zenodo 8263181, CC-BY-4.0): 2.6M real Wazuh alerts from 8 independent
testbeds, with ground truth published as attack-phase start/end times. Its
loaders here are deliberately thin — windows, a containment test, and a raw
alert iterator — because the featurisation belongs to the *production* code
path (`modules.collector` -> `modules.feature_extractor`), and `ml/train.py`
drives that.

Everything else in this module is the retired ALERT_FEATURE_COLUMNS world (the
24 Wazuh-metadata columns), kept for the tests that document why it was
retired. Nothing trains on it.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

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
AIT_LABELS_CSV = AIT_ADS_DIR / "labels.csv"
# AIT Alert Data Set — Landauer, Skopik & Wurzenberger, Zenodo record 8263181,
# CC-BY-4.0. 2.6M Wazuh alerts from 8 independent testbeds, ground truth given
# as attack-phase [start, end] UNIX epochs in labels.csv.
AIT_ADS_ZENODO = "https://zenodo.org/records/8263181/files"
AIT_SCENARIOS = (
    "fox", "harrison", "russellmitchell", "santos",
    "shaw", "wardbeck", "wheeler", "wilson",
)


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


def _ait_alert_label(event_epoch: float, windows: Sequence[tuple[float, float]]) -> int:
    """Ground truth for one AIT-ADS alert: 1 inside a published attack phase.

    The *only* input is when the alert happened. `labels.csv` publishes each
    testbed's attack phases as [start, end] UNIX epochs in UTC, and every AIT
    alert carries `@timestamp` as UTC ISO-8601 ("…Z"), so the join is a plain
    numeric containment test with no offset to get wrong. Verified against the
    data: all 7 664 russellmitchell web-access alerts land inside the
    service_scans→webshell phases and none outside them.

    Nothing about the alert's own severity, signature id or decoder is
    consulted. That is the point of ML-12: the label is not merely *chosen* not
    to depend on Wazuh's verdict, it is unable to — the verdict is not
    reachable from this function's arguments. ML-1's leak cannot come back by
    someone editing a heuristic in a hurry.

    The published windows are per-testbed, not per-host, so a benign mail login
    that happens during an attack phase is labelled attack. That is the ground
    truth as the authors released it; it adds label noise and it is the
    dataset's own definition, not ours.
    """
    return int(any(start <= event_epoch <= end for start, end in windows))


def ensure_ait_ads(*, directory: Path | None = None) -> Path:
    """Download + unzip AIT-ADS into ml/datasets/ait-ads/ (gitignored, ~2.8 GB)."""
    import urllib.request
    import zipfile

    root = directory or AIT_ADS_DIR
    root.mkdir(parents=True, exist_ok=True)
    labels = root / "labels.csv"
    if not labels.is_file():
        urllib.request.urlretrieve(f"{AIT_ADS_ZENODO}/labels.csv?download=1", labels)

    if not any(root.glob("*_wazuh.json")):
        archive = root / "ait_ads.zip"
        if not archive.is_file():
            print(f"Downloading AIT-ADS (~96 MB zipped) to {root} …")
            urllib.request.urlretrieve(f"{AIT_ADS_ZENODO}/ait_ads.zip?download=1", archive)
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(root)
    return root


def load_ait_attack_windows(
    labels_csv: Path | None = None,
) -> dict[str, list[tuple[float, float]]]:
    """Parse labels.csv -> {scenario: [(start_epoch, end_epoch), …]}."""
    import csv

    path = labels_csv or AIT_LABELS_CSV
    windows: dict[str, list[tuple[float, float]]] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            windows.setdefault(row["scenario"], []).append(
                (float(row["start"]), float(row["end"]))
            )
    return windows


def iter_ait_alerts(
    scenario: str,
    *,
    directory: Path | None = None,
    windows: dict[str, list[tuple[float, float]]] | None = None,
) -> Iterable[tuple[dict, float, int]]:
    """Yield (alert, event_epoch, label) for one testbed, in log order.

    The files are JSON-lines and already sorted by `@timestamp` (checked), which
    matters: the rolling window is fed in arrival order exactly as production
    feeds it, so replaying a file is replaying the testbed.
    """
    root = directory or AIT_ADS_DIR
    phases = (windows or load_ait_attack_windows()).get(scenario, [])
    path = root / f"{scenario}_wazuh.json"
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            stamp = alert.get("@timestamp") or alert.get("timestamp")
            if not isinstance(alert, dict) or not stamp:
                continue
            epoch = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp()
            yield alert, epoch, _ait_alert_label(epoch, phases)


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
    true_labeled_max_rows: int | None = 200_000,
    hf_max_rows: int | None = None,
    seed: int = 42,
) -> tuple[pd.DataFrame, dict[str, int]]:
    """Merge the retired ALERT_FEATURE_COLUMNS sources. AIT-ADS is not one of them:
    it feeds the behavioural f1..f8 contract via `ml.train.build_ait_dataset`."""
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
