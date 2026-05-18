import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import numpy as np
import pytest

from config import settings
from modules.decision_policy import _apply_min_attempts_gate, process_event
from schemas.normalized_event import NormalizedEvent


def test_min_attempts_gate_caps_score():
    settings.thresholds.t1 = 0.55
    settings.min_attempts_for_alert = 8
    capped = _apply_min_attempts_gate(0.9, 2.0, 0.55)
    assert capped < 0.55
    uncapped = _apply_min_attempts_gate(0.9, 10.0, 0.55)
    assert uncapped == 0.9


@pytest.mark.asyncio
async def test_whitelisted_ip_skips_telegram():
    event = NormalizedEvent(
        src_ip="10.0.0.5",
        channel="sshd",
        event_type="auth_failed",
        username="root",
    )
    db = AsyncMock()
    db.add = lambda *a, **k: None
    db.commit = AsyncMock()
    db.refresh = AsyncMock()

    with (
        patch("modules.decision_policy._is_whitelisted", return_value=True),
        patch("modules.decision_policy.crud.insert_event", new=AsyncMock()),
        patch("modules.decision_policy.crud.insert_decision", new=AsyncMock()),
        patch("modules.alerting.send_alert", new=AsyncMock()) as mock_tg,
        patch("modules.feature_extractor.extract_ssh_features") as mock_x,
    ):
        mock_x.return_value = np.zeros(8, dtype=np.float32)
        await process_event(event, db)

    mock_tg.assert_not_called()
