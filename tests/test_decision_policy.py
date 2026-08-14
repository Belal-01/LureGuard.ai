"""Tests for threshold logic and decision_policy helpers."""
import pytest
from unittest.mock import AsyncMock, patch

from modules.decision_policy import decide, process_event, update_whitelist


@pytest.mark.parametrize(
    "p,expected",
    [
        (0.1, "allow"),
        (0.39, "allow"),
        (0.40, "allow"),
        (0.41, "alert"),
        (0.70, "alert"),
        (0.71, "redirect"),
        (0.99, "redirect"),
    ],
)
def test_decide_thresholds(p: float, expected: str):
    assert decide(p, t1=0.40, t2=0.70) == expected


@pytest.mark.asyncio
async def test_process_event_allow_no_enforcement():
    from schemas.normalized_event import NormalizedEvent

    event = NormalizedEvent(
        src_ip="10.0.0.99",
        channel="sshd",
        event_type="auth_failed",
        username="root",
    )
    db = AsyncMock()

    with (
        patch("modules.inference.infer", return_value={"p": 0.1, "model_version": "test"}),
        patch("modules.feature_extractor.extract_ssh_features") as mock_features,
        patch("modules.decision_policy.crud.insert_event", new=AsyncMock()),
        patch("modules.decision_policy.crud.insert_decision", new=AsyncMock()) as mock_dec,
        patch("modules.alerting.send_alert", new=AsyncMock()),
    ):
        import numpy as np

        mock_features.return_value = np.zeros(8, dtype=np.float32)
        update_whitelist([])
        await process_event(event, db)

    assert mock_dec.await_args.args[1].decision == "allow"


@pytest.mark.asyncio
async def test_process_event_redirect_recommends_without_enforcing():
    from schemas.normalized_event import NormalizedEvent

    event = NormalizedEvent(
        src_ip="10.0.0.99",
        channel="sshd",
        event_type="auth_failed",
        username="postgres",
    )
    db = AsyncMock()

    with (
        patch("modules.inference.infer", return_value={"p": 0.95, "model_version": "test"}),
        patch("modules.feature_extractor.extract_ssh_features") as mock_features,
        patch("modules.decision_policy.crud.insert_event", new=AsyncMock()),
        patch("modules.decision_policy.crud.insert_decision", new=AsyncMock()) as mock_dec,
        patch("modules.alerting.send_alert", new=AsyncMock()),
    ):
        import numpy as np

        feats = np.ones(8, dtype=np.float32)
        feats[0] = 10.0  # past min_attempts_for_alert gate
        mock_features.return_value = feats
        update_whitelist([])
        await process_event(event, db)

    # Records the recommendation (which honeypot profile) but enforces nothing:
    # core has no iptables path at all now. Containment is human-gated via MCP.
    dec = mock_dec.await_args.args[1]
    assert dec.decision == "redirect"
    assert dec.profile_id == "db-server"
    assert "not applied" in dec.reason
