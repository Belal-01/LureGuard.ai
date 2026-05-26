"""
ML Inference — loads offline-trained model.joblib (real datasets only at train time).
"""
from __future__ import annotations

import hashlib
import json
import warnings
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from ml.feature_contract import FEATURE_COLUMNS
from runtime.paths import models_dir

_model = None
_scaler = None
_model_version = "stub-0.0.0"
_feature_columns: list[str] = list(FEATURE_COLUMNS)


def _models_path() -> Path:
    return models_dir()


def load_model() -> None:
    """Load artifacts and verify SHA-256 when registry is active."""
    global _model, _scaler, _model_version, _feature_columns

    base = _models_path()
    registry_path = base / "model_registry.json"
    model_path = base / "model.joblib"
    scaler_path = base / "scaler.joblib"

    if not model_path.exists() or not scaler_path.exists():
        warnings.warn(
            f"ML artifacts missing under {base} — running in stub mode (p=0.0)",
            stacklevel=2,
        )
        return

    import joblib

    if registry_path.exists():
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        if registry.get("active") and registry.get("sha256"):
            actual_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
            if actual_hash != registry["sha256"]:
                raise RuntimeError(
                    f"model.joblib SHA-256 mismatch! "
                    f"Expected: {registry['sha256']} | Got: {actual_hash}"
                )
        _model_version = registry.get("version", "unknown")
        cols = registry.get("feature_columns")
        if isinstance(cols, list) and cols:
            _feature_columns = [str(c) for c in cols]
    else:
        _model_version = "unregistered"

    _scaler = joblib.load(scaler_path)
    _model = joblib.load(model_path)


def get_model_version() -> str:
    return _model_version


def get_feature_columns() -> list[str]:
    return list(_feature_columns)


def infer(x_raw: np.ndarray | None = None, *, feature_row: dict[str, float] | None = None) -> dict:
    """Run inference on feature_row (production) or legacy 8-vector x_raw."""
    if _model is None or _scaler is None:
        return {"p": 0.0, "model_version": _model_version}

    if feature_row is not None:
        frame = pd.DataFrame([feature_row], columns=_feature_columns)
    elif x_raw is not None:
        if len(_feature_columns) != len(x_raw):
            warnings.warn(
                f"Feature dim mismatch: model expects {len(_feature_columns)}, got {len(x_raw)}",
                stacklevel=2,
            )
            return {"p": 0.0, "model_version": _model_version}
        frame = pd.DataFrame([x_raw.tolist()], columns=_feature_columns)
    else:
        return {"p": 0.0, "model_version": _model_version}

    scaled = _scaler.transform(frame)
    p = float(_model.predict_proba(scaled)[0, 1])
    return {"p": p, "model_version": _model_version}


def infer_event(feature_row: dict[str, Any]) -> dict:
    """Score a normalized alert feature dict from live Wazuh traffic."""
    row = {k: float(feature_row.get(k, 0.0)) for k in _feature_columns}
    return infer(feature_row=row)
