"""
Feature extraction — rolling-window f1..f8 via shared ml.extractor.

ML-2: these are the only features the model scores, and they are all functions
of a source's recent history rather than of the single event in hand. See
ml/feature_contract.py for what each one means.

Channel-generic (ML-2's fix generalised): "target" is the thing the source is
trying, and only its field differs per channel —

    sshd  -> username
    web   -> request path

— so one contract, one model, and a web scan is the same shape as an SSH brute
force instead of a case the auth-shaped extractor could not see.
"""
from __future__ import annotations

import re
from datetime import timezone

import numpy as np

from runtime.window_store import get_extractor
from runtime.whitelist import is_whitelisted
from schemas.normalized_event import NormalizedEvent

# `1.2.3.4 - - "GET /wp-login.php HTTP/1.1" 404 162` — the combined-log shape
# Wazuh's web-accesslog decoder emits. Group 1 is the path, group 2 the status.
_ACCESS_LOG = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+(\S+)[^"]*"\s+(\d{3})')


def _web_path_and_status(raw: str) -> tuple[str | None, int | None]:
    match = _ACCESS_LOG.search(raw or "")
    if not match:
        return None, None
    # Strip the query string: /search?q=a and /search?q=b are one target, and
    # counting them as two would let a single-endpoint retry storm look like a
    # sweep across many paths.
    return match.group(1).split("?", 1)[0], int(match.group(2))


def _target_and_status(event: NormalizedEvent) -> tuple[str, str]:
    """Return (target, status) — what the source tried, and whether it worked."""
    channel = (event.channel or "").lower()

    if channel == "web":
        path, code = _web_path_and_status(event.raw_ref)
        target = path or "unknown"
        if code is not None:
            status = "failed" if code >= 400 else "success"
        else:
            # No parseable status line: fall back to the normalized flag rather
            # than guessing "failed", which would peg f2 at 1.0 for the whole
            # channel and make the failure ratio carry no information.
            status = "success" if event.success else "failed"
        return target, status

    # sshd and everything else: the account being attempted, and whether the
    # attempt succeeded.
    target = event.username or "unknown"
    if event.event_type == "auth_failed":
        return target, "failed"
    if event.event_type == "auth_success":
        return target, "success"
    return target, "success" if event.success else "unknown"


def extract_event_features(event: NormalizedEvent) -> np.ndarray:
    """Ingest one event and return the raw behavioural vector f1..f8."""
    event_ts = event.ts if event.ts.tzinfo else event.ts.replace(tzinfo=timezone.utc)
    whitelisted = is_whitelisted(event.src_ip, event.username, event_ts)
    ts_iso = event.ts.isoformat()
    if not ts_iso.endswith("Z") and "+" not in ts_iso:
        ts_iso = ts_iso + "Z"

    target, status = _target_and_status(event)

    features = get_extractor().update_from_raw(
        src_ip=event.src_ip or "0.0.0.0",
        username=target,
        status=status,
        event_timestamp=ts_iso,
        is_whitelist=whitelisted,
    )
    return np.array(features, dtype=np.float32)


# The window is keyed per source and per target, not per channel, so the SSH
# call site keeps its name. decision_policy.py imports this symbol and is owned
# by another stream — renaming it there is not this change's business.
extract_ssh_features = extract_event_features


def features_to_row(x: np.ndarray) -> dict[str, float]:
    """Vector -> the {f1..f8} dict `inference.infer_event` scores."""
    return {f"f{i}": float(v) for i, v in enumerate(x, start=1)}
