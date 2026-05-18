"""Tests for modules.inference."""
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest

from ml.feature_contract import FEATURE_COLUMNS


@pytest.fixture
def models_path() -> Path:
    return Path(__file__).resolve().parents[1] / "ml" / "models"


def test_infer_stub_when_no_model():
    import modules.inference as inf

    inf._model = None
    inf._scaler = None
    result = inf.infer(np.zeros(8, dtype=np.float32))
    assert result["p"] == 0.0
    assert "model_version" in result


def test_load_model_from_repo_artifacts(models_path: Path):
    if not (models_path / "model.joblib").exists():
        pytest.skip("ml/models artifacts not present")

    import modules.inference as inf

    with patch("modules.inference.models_dir", return_value=models_path):
        inf._model = None
        inf._scaler = None
        inf.load_model()

    raw = np.array([5, 0.8, 2, 3, 1.0, 0.2, 0.6, 0], dtype=np.float32)
    result = inf.infer(raw)
    assert 0.0 <= result["p"] <= 1.0
    assert result["model_version"] != "stub-0.0.0"


def test_feature_columns_length():
    assert len(FEATURE_COLUMNS) == 8
