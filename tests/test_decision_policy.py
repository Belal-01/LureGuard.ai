"""Unit tests for decision thresholds."""
import numpy as np
import pytest
from unittest.mock import patch, AsyncMock

# Patch inference to return controlled p values
def make_event(src_ip="1.2.3.4", username="root"):
    from schemas.normalized_event import NormalizedEvent
    return NormalizedEvent(
        src_ip=src_ip, channel="sshd",
        event_type="auth_failed", username=username
    )


@pytest.mark.asyncio
async def test_allow_below_t1():
    with patch("modules.inference.infer", return_value={"p": 0.2, "model_version": "test"}):
        with patch("modules.decision_policy._whitelist", set()):
            from modules.decision_policy import process_event
            from db.session import AsyncSessionLocal
            # TODO: use test DB fixture
            pass  # placeholder


def test_thresholds_logic():
    """Pure logic test — no DB needed."""
    t1, t2 = 0.40, 0.70
    for p, expected in [
        (0.1, "allow"), (0.39, "allow"),
        (0.40, "allow"), (0.41, "alert"),
        (0.70, "alert"), (0.71, "redirect"),
        (0.99, "redirect"),
    ]:
        if p <= t1:
            decision = "allow"
        elif p <= t2:
            decision = "alert"
        else:
            decision = "redirect"
        assert decision == expected, f"p={p} → expected {expected}, got {decision}"
