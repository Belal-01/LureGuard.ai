"""
Decision Policy — orchestrates the full pipeline for each event.

Flow:
  NormalizedEvent
    → (SSH only) Feature Extraction
    → ML Inference → p ∈ [0,1]
    → Whitelist check
    → Threshold comparison → allow | alert | redirect
    → Profile selection (if redirect)
    → Enforcer (iptables DNAT)
    → DB write (DECISION)
    → Telegram alert (if alert/redirect)
"""
import uuid
import hashlib
from datetime import datetime

import numpy as np
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import crud
from modules import feature_extractor, inference
from modules.profile_selector import select_profile
from modules.enforcer import apply_dnat
from schemas.normalized_event import NormalizedEvent
from schemas.decision_result import DecisionResult

# In-memory whitelist cache (refreshed from DB periodically)
_whitelist: set[str] = set()


def update_whitelist(ips: list[str]) -> None:
    global _whitelist
    _whitelist = set(ips)


async def process_event(event: NormalizedEvent, db: AsyncSession) -> None:
    """Main entry point called by the Wazuh endpoint for every event."""

    # 1. Persist the raw event
    await crud.insert_event(db, event)

    # 2. Only SSH auth events feed the classifier
    if event.channel != "sshd" or event.event_type not in ("auth_failed", "auth_success"):
        _handle_non_ssh(event)
        return

    # 3. Build feature vector (علي implements this in Sprint 2)
    events_window = []   # TODO: fetch from in-memory window store
    x: np.ndarray = feature_extractor.extract_features(event.src_ip or "", events_window)

    # 4. Whitelist short-circuit
    if event.src_ip in _whitelist:
        x[7] = 1.0   # f8 = is_known_good
        result = inference.infer(np.zeros(8))
        p = 0.0
    else:
        result = inference.infer(x)
        p = result["p"]

    # 5. Decision
    t1, t2 = settings.thresholds.t1, settings.thresholds.t2
    if p <= t1:
        decision = "allow"
        reason = f"p={p:.3f} ≤ T1={t1} → ALLOW"
    elif p <= t2:
        decision = "alert"
        reason = f"p={p:.3f} ∈ (T1={t1}, T2={t2}] → ALERT"
    else:
        decision = "redirect"
        profile_id = select_profile(event.username or "", p)
        reason = f"p={p:.3f} > T2={t2} → REDIRECT to {profile_id} (user={event.username})"

    # 6. Profile selection + Enforcement
    profile_id = None
    if decision == "redirect":
        profile_id = select_profile(event.username or "", p)
        apply_dnat(event.src_ip or "", profile_id)

    # 7. Persist DECISION
    dec = DecisionResult(
        id=uuid.uuid4(),
        ts=datetime.utcnow(),
        decision=decision,
        p=p,
        score=p,
        t1=t1,
        t2=t2,
        model_version=result.get("model_version", "stub"),
        features_hash=hashlib.md5(x.tobytes()).hexdigest(),
        profile_id=profile_id,
        reason=reason,
    )
    await crud.insert_decision(db, dec)

    logger.info(f"[{event.src_ip}] {reason}")

    # 8. Telegram alert (if alert or redirect)
    if decision in ("alert", "redirect"):
        from modules.alerting import send_alert
        await send_alert(dec, event)


def _handle_non_ssh(event: NormalizedEvent) -> None:
    """Handle FIM / rootcheck events — Telegram only, no ML."""
    from modules.alerting import send_non_ssh_alert
    import asyncio
    if event.channel in ("syscheck", "rootcheck") and event.wazuh_rule_level >= 7:
        asyncio.create_task(send_non_ssh_alert(event))
