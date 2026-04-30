"""
ML Inference module.
Loads model.joblib + scaler.joblib on startup.
Exposes: infer(x: np.ndarray) -> dict

⚠️  STUB — جلال يكمل التنفيذ الحقيقي في Sprint 2.
"""
import hashlib
import json
from pathlib import Path
from typing import Optional

import numpy as np

# Will be populated by load_model()
_model = None
_scaler = None
_model_version = "stub-0.0.0"

MODELS_DIR = Path("/app/models")


def load_model() -> None:
    """
    Called once at startup.
    Verifies SHA-256 against model_registry.json then loads .joblib files.
    """
    global _model, _scaler, _model_version

    registry_path = MODELS_DIR / "model_registry.json"
    model_path    = MODELS_DIR / "model.joblib"
    scaler_path   = MODELS_DIR / "scaler.joblib"

    if not model_path.exists():
        # Sprint 1: no model yet — run in stub mode
        import warnings
        warnings.warn("model.joblib not found — running in STUB mode (p always 0.0)")
        return

    # Verify SHA-256
    registry = json.loads(registry_path.read_text())
    actual_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    if actual_hash != registry.get("sha256"):
        raise RuntimeError(
            f"model.joblib SHA-256 mismatch! "
            f"Expected: {registry['sha256']} | Got: {actual_hash}\n"
            "Refusing to start — possible model tampering."
        )

    import joblib
    _scaler = joblib.load(scaler_path)
    _model  = joblib.load(model_path)
    _model_version = registry.get("version", "unknown")


def infer(x: np.ndarray) -> dict:
    """
    Run inference on a feature vector.

    Args:
        x: shape (8,) — [f1..f8] scaled values

    Returns:
        {"p": float, "model_version": str}
    """
    if _model is None:
        # Stub mode: return safe default
        return {"p": 0.0, "model_version": "stub-0.0.0"}

    x_2d = x.reshape(1, -1)
    p = float(_model.predict_proba(x_2d)[0, 1])
    return {"p": p, "model_version": _model_version}
