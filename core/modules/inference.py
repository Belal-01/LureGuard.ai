"""
ML Inference — loads model.joblib + scaler.joblib from MODELS_DIR / ml/models.
"""
from __future__ import annotations

import hashlib
import json
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

from ml.feature_contract import FEATURE_COLUMNS
from runtime.paths import models_dir

_model = None
_scaler = None
_model_version = "stub-0.0.0"


def _models_path() -> Path:
    return models_dir()


def load_model() -> None:
    """Load artifacts and verify SHA-256 when registry is active."""
    global _model, _scaler, _model_version

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
    else:
        _model_version = "unregistered"

    _scaler = joblib.load(scaler_path)
    _model = joblib.load(model_path)


def get_model_version() -> str:
    return _model_version


def infer(x_raw: np.ndarray) -> dict:
    """Run inference on raw features f1..f8 (scaler applied here)."""
    if _model is None or _scaler is None:
        return {"p": 0.0, "model_version": _model_version}

    frame = pd.DataFrame([x_raw.tolist()], columns=FEATURE_COLUMNS)
    scaled = _scaler.transform(frame)
    p = float(_model.predict_proba(scaled)[0, 1])
    return {"p": p, "model_version": _model_version}
