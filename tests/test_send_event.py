"""
Integration tests — synthetic Wazuh SSH brute-force alert through the Core pipeline.

Run locally (mocked DB):
  pytest tests/test_send_event.py -v

POST to running Core (requires make core):
  pytest tests/test_send_event.py -v -m integration
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

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


def _reload_telegram_notifier() -> None:
    import importlib

    import connectors.telegram as tg
    import modules.alerting as alerting

    importlib.reload(tg)
    alerting.telegram_notifier = tg.TelegramNotifier()


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

    _reload_telegram_notifier()

    with patch("modules.decision_policy.apply_dnat"):
        await process_event(event, db)

    return {
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "channel": event.channel,
    }


@pytest.mark.asyncio
async def test_bruteforce_pipeline_redirect_decision(bruteforce_alert: dict) -> None:
    """12 failed attempts + one alert should score above T2 (redirect)."""
    from modules.decision_policy import decide
    from modules.inference import infer
    from modules.feature_extractor import extract_ssh_features
    from modules.collector import normalize_event
    from schemas.wazuh_alert import WazuhAlert
    from runtime.window_store import get_extractor, reset_extractor
    from modules.inference import load_model

    load_model()
    reset_extractor()
    extractor = get_extractor()
    base = datetime.now(tz=timezone.utc)
    for _ in range(12):
        ts = base.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        extractor.update_from_raw(BRUTEFORCE_IP, "root", "failed", ts)

    event = normalize_event(WazuhAlert.model_validate(bruteforce_alert))
    features = extract_ssh_features(event)
    p = infer(features)["p"]

    assert decide(p, t1=0.40, t2=0.70) == "redirect"
    assert p > 0.70


@pytest.mark.asyncio
async def test_bruteforce_pipeline_runs_with_mocked_db(bruteforce_alert: dict) -> None:
    result = await _run_pipeline(bruteforce_alert)
    assert result["event_type"] == "auth_failed"
    assert result["src_ip"] == BRUTEFORCE_IP
    assert result["channel"] == "sshd"


@pytest.mark.integration
def test_post_wazuh_event_to_running_core(bruteforce_alert: dict) -> None:
    """POST /wazuh/event when Core is up (make core). Skips if unreachable."""
    body = json.dumps(bruteforce_alert).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8080/wazuh/event",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        pytest.skip(f"Core not reachable on :8080 ({exc})")

    assert resp.status == 202
    assert payload.get("status") == "queued"
