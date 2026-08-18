"""
Integration tests — synthetic Wazuh SSH brute-force alert through the Core pipeline.

Run locally (mocked DB):
  pytest tests/test_send_event.py -v

POST to running Core (requires `docker compose up -d`):
  pytest tests/test_send_event.py -v -m integration
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

BRUTEFORCE_IP = "198.51.100.77"


@pytest.fixture
def bruteforce_alert() -> dict:
    return {
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {
            "id": 5710,
            "level": 10,
            "description": "sshd: authentication failed",
            "groups": ["authentication_failed", "sshd"],
        },
        "agent": {"id": "002", "name": "test-host"},
        "data": {"srcip": BRUTEFORCE_IP, "srcuser": "root"},
        "full_log": f"Failed password for root from {BRUTEFORCE_IP} port 22 ssh2",
    }


@pytest.fixture(autouse=True)
def _pipeline_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONFIG_PATH", str(REPO_ROOT / "config" / "core.yaml"))
    monkeypatch.setenv("MODELS_DIR", str(REPO_ROOT / "ml" / "models"))


async def _run_pipeline(bruteforce_alert: dict) -> dict:
    from modules.collector import normalize_event
    from modules.decision_policy import process_event
    from modules.inference import load_model
    from runtime.window_store import get_extractor, reset_extractor
    from schemas.wazuh_alert import WazuhAlert

    load_model()
    reset_extractor()
    extractor = get_extractor()

    base = datetime.now(tz=timezone.utc)
    for _ in range(12):
        ts = base.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        extractor.update_from_raw(
            src_ip=BRUTEFORCE_IP,
            username="root",
            status="failed",
            event_timestamp=ts,
        )

    alert = WazuhAlert.model_validate(bruteforce_alert)
    event = normalize_event(alert)
    db = AsyncMock()
    db.add = lambda *a, **k: None
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    geo_result = MagicMock()
    geo_result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=geo_result)

    with patch("modules.alerting.send_alert", new=AsyncMock()):
        await process_event(event, db)

    return {
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "channel": event.channel,
    }


@pytest.mark.asyncio
async def test_bruteforce_pipeline_redirect_decision(bruteforce_alert: dict) -> None:
    """12 failed attempts from one source must escalate to a redirect.

    ML-8: this used to assert the *classifier* scored the event above T2, by
    feeding featurize_normalized_event's 24 Wazuh-metadata features to the
    model. SSH no longer goes through the model at all — Wazuh rule 5712
    already correlates 8 failures in 120s from one source, and reimplementing
    that in Python is what let our score veto a confirmed detection.

    The property under test is unchanged and still worth holding: a sustained
    brute force must escalate. Only the mechanism moved, from a probability to
    the rule that fires.
    """
    from modules.collector import normalize_event
    from modules.decision_policy import _ssh_verdict, decide
    from runtime.window_store import get_extractor, reset_extractor
    from schemas.wazuh_alert import WazuhAlert

    reset_extractor()
    extractor = get_extractor()
    base = datetime.now(tz=timezone.utc)
    for _ in range(12):
        ts = base.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        extractor.update_from_raw(BRUTEFORCE_IP, "root", "failed", ts)

    event = normalize_event(WazuhAlert.model_validate(bruteforce_alert))
    p = _ssh_verdict(event, attempts=12)

    assert p == 1.0, "a sustained brute force is a rule that fired, not a probability"
    assert decide(p, t1=0.40, t2=0.70) == "redirect"

    # And the inverse, so this cannot pass by always returning 1.0: a single
    # failure with no Wazuh escalation must not escalate.
    quiet = normalize_event(WazuhAlert.model_validate(bruteforce_alert))
    quiet.wazuh_rule_level = 5
    assert _ssh_verdict(quiet, attempts=1) == 0.0


@pytest.mark.asyncio
async def test_bruteforce_pipeline_runs_with_mocked_db(bruteforce_alert: dict) -> None:
    result = await _run_pipeline(bruteforce_alert)
    assert result["event_type"] == "auth_failed"
    assert result["src_ip"] == BRUTEFORCE_IP
    assert result["channel"] == "sshd"


@pytest.mark.integration
def test_post_wazuh_event_to_running_core(bruteforce_alert: dict) -> None:
    """POST /wazuh/event when Core container is up. Skips if unreachable."""
    import os

    body = json.dumps(bruteforce_alert).encode("utf-8")
    token = os.getenv("INGEST_TOKEN", "lureguard-dev-ingest-token")
    req = urllib.request.Request(
        "http://127.0.0.1:8080/wazuh/event",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-LureGuard-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        pytest.skip(f"Core not reachable on :8080 ({exc})")

    assert resp.status == 200
    assert payload.get("status") == "processed"
