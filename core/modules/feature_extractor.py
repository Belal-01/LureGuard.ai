"""
Feature extraction — rolling-window f1..f8 via shared ml.extractor.
"""
from __future__ import annotations

from datetime import timezone

import numpy as np

from runtime.window_store import get_extractor
from runtime.whitelist import is_whitelisted
from schemas.normalized_event import NormalizedEvent


def _auth_status(event: NormalizedEvent) -> str:
    if event.event_type == "auth_failed":
        return "failed"
    if event.event_type == "auth_success":
        return "success"
    return "unknown"


def extract_ssh_features(event: NormalizedEvent) -> np.ndarray:
    """Ingest one SSH auth event and return raw feature vector f1..f8."""
    event_ts = event.ts if event.ts.tzinfo else event.ts.replace(tzinfo=timezone.utc)
    whitelisted = is_whitelisted(event.src_ip, event.username, event_ts)
    ts_iso = event.ts.isoformat()
    if not ts_iso.endswith("Z") and "+" not in ts_iso:
        ts_iso = ts_iso + "Z"
    features = get_extractor().update_from_raw(
        src_ip=event.src_ip or "0.0.0.0",
        username=event.username or "unknown",
        status=_auth_status(event),
        event_timestamp=ts_iso,
        is_whitelist=whitelisted,
    )
    return np.array(features, dtype=np.float32)
