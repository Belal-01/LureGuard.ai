"""Shared pytest fixtures and runtime resets."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = REPO_ROOT / "core"

for path in (str(REPO_ROOT), str(CORE_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)


@pytest.fixture(autouse=True)
def _no_real_telegram(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests must not call the Telegram API (set TELEGRAM_LIVE_TESTS=1 to opt in)."""
    if os.getenv("TELEGRAM_LIVE_TESTS") == "1":
        return

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "")

    async def _noop_send_alert(*_args, **_kwargs) -> None:
        return None

    monkeypatch.setattr(
        "modules.alerting.send_alert",
        AsyncMock(side_effect=_noop_send_alert),
        raising=False,
    )
    monkeypatch.setattr(
        "modules.alerting.send_non_ssh_alert",
        AsyncMock(side_effect=_noop_send_alert),
        raising=False,
    )


@pytest.fixture(autouse=True)
def _reset_runtime_singletons():
    """Isolate tests that use in-memory extractor / whitelist state."""
    from runtime import whitelist as wl
    from runtime import window_store as ws

    ws.reset_extractor()
    wl.reset_whitelist_cache()
    yield
    ws.reset_extractor()
    wl.reset_whitelist_cache()


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def ssh_failed_alert() -> dict:
    return {
        "timestamp": "2026-05-20T14:31:02.000+0000",
        "rule": {
            "id": 5710,
            "level": 10,
            "description": "sshd: authentication failed",
            "groups": ["authentication_failed", "sshd"],
        },
        "agent": {"id": "002", "name": "target-host"},
        "data": {"srcip": "203.0.113.17", "srcuser": "root"},
        "full_log": "Failed password for root from 203.0.113.17",
    }


@pytest.fixture
def wazuh_alert_model(ssh_failed_alert):
    from schemas.wazuh_alert import WazuhAlert

    return WazuhAlert.model_validate(ssh_failed_alert)


@pytest.fixture
def whitelist_config(tmp_path: Path) -> Path:
    path = tmp_path / "whitelist.json"
    path.write_text(
        json.dumps(
            {
                "entries": [
                    {"ip": "10.0.0.1", "user": "admin"},
                    {"cidr": "192.168.0.0/24"},
                ]
            }
        ),
        encoding="utf-8",
    )
    return path
