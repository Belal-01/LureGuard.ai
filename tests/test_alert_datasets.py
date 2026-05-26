"""Tests for multi-dataset alert feature loading (no full CSV scan)."""
from __future__ import annotations

import json

import pandas as pd
import pytest

from ml.alert_features import (
    normalize_label,
    true_labeled_row_to_features,
)
from ml.dataset_loaders import (
    fetch_hf_wazuh_alerts_cache,
    load_hf_wazuh_alerts,
    load_true_labeled_dataset,
    TRUE_LABELED_CSV,
)


def test_normalize_attack_label():
    assert normalize_label("Normal") == 0
    assert normalize_label("dirb") == 1
    assert normalize_label("True Positive") == 1
    assert normalize_label("False Positive") == 0


def test_true_labeled_row_features():
    row = pd.Series(
        {
            "rule_level": 5,
            "rule_id": 5710,
            "decoder_name": "sshd",
            "src_ip": "10.0.0.1",
            "attack_label": "wpscan",
        }
    )
    feats = true_labeled_row_to_features(row)
    assert feats["is_sshd"] == 1.0
    assert feats["has_srcip"] == 1.0
    assert feats["rule_id"] == 5710.0


@pytest.mark.skipif(not TRUE_LABELED_CSV.is_file(), reason="true_labeled_dataset.csv not present")
def test_load_true_labeled_sample():
    df = load_true_labeled_dataset(max_rows=500, seed=1)
    assert len(df) <= 500
    assert "target" in df.columns
    assert df["target"].isin([0, 1]).all()
    assert df["source"].iloc[0] == "true_labeled"


def test_load_hf_from_cache(tmp_path, monkeypatch):
    cache = tmp_path / "hf.json"
    sample = {
        "rows": [
            {
                "row": {
                    "input": json.dumps(
                        {
                            "timestamp": "2025-03-05T00:03:46.096+0000",
                            "rule": {"level": 5, "id": "5710", "groups": ["sshd"]},
                            "data": {"srcip": "1.2.3.4", "srcuser": "root"},
                            "full_log": "Invalid user root",
                            "decoder": {"name": "sshd"},
                        }
                    ),
                    "output": "True Positive",
                }
            }
        ]
    }
    cache.write_text(json.dumps(sample), encoding="utf-8")
    df = load_hf_wazuh_alerts(cache_path=cache, use_datasets_library=False)
    assert len(df) == 1
    assert df["target"].iloc[0] == 1
