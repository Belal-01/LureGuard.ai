"""
Decision Policy — orchestrates the full pipeline for each event.
"""
import hashlib
import uuid
from datetime import datetime, timezone

import numpy as np
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import crud
from modules import feature_extractor, inference
from modules.profile_selector import select_profile
from modules.enforcer import apply_dnat
from runtime import whitelist as whitelist_cache
from schemas.normalized_event import NormalizedEvent
from schemas.decision_result import DecisionResult


def decide(p: float, t1: float, t2: float) -> str:
    if p <= t1:
        return "allow"
    if p <= t2:
        return "alert"
    return "redirect"


def update_whitelist(ips: list[str]) -> None:
    """Test helper — production uses Postgres via runtime.whitelist cache."""
    whitelist_cache.refresh_cache(ips)


def _is_whitelisted(event: NormalizedEvent) -> bool:
    return whitelist_cache.is_whitelisted(event.src_ip, event.username, event.ts)


def _apply_min_attempts_gate(p: float, attempt_count: float, t1: float) -> float:
    """Do not treat a handful of typos as an attack — need sustained volume."""
    minimum = settings.min_attempts_for_alert
    if attempt_count < minimum:
        return min(p, t1 - 1e-6)
    return p


async def process_event(event: NormalizedEvent, db: AsyncSession) -> None:
    await crud.insert_event(db, event)

    if event.channel != "sshd" or event.event_type not in ("auth_failed", "auth_success"):
        _handle_non_ssh(event)
        return

    if _is_whitelisted(event):
        x_ssh = feature_extractor.extract_ssh_features(event)
        p = 0.0
        decision = "allow"
        reason = f"whitelisted IP {event.src_ip} → ALLOW"
        result = {"model_version": inference.get_model_version()}
        logger.info(f"[{event.src_ip}] {reason}")
        dec = DecisionResult(
            id=uuid.uuid4(),
            ts=datetime.utcnow(),
            decision=decision,
            p=p,
            score=p,
            t1=settings.thresholds.t1,
            t2=settings.thresholds.t2,
            model_version=result.get("model_version", "stub"),
            features_hash=hashlib.md5(x_ssh.tobytes()).hexdigest(),
            profile_id=None,
            reason=reason,
        )
        await crud.insert_decision(db, dec)
        return

    from ml.alert_features import featurize_normalized_event

    x_ssh = feature_extractor.extract_ssh_features(event)
    feat = featurize_normalized_event(event)
    result = inference.infer_event(feat)
    p = result["p"]
    p = _apply_min_attempts_gate(p, float(x_ssh[0]), settings.thresholds.t1)

    t1, t2 = settings.thresholds.t1, settings.thresholds.t2
    decision = decide(p, t1, t2)
    if decision == "allow":
        reason = f"p={p:.3f} ≤ T1={t1} → ALLOW (attempts={int(x_ssh[0])})"
    elif decision == "alert":
        reason = f"p={p:.3f} ∈ (T1={t1}, T2={t2}] → ALERT (attempts={int(x_ssh[0])})"
    else:
        profile_id = select_profile(event.username or "", p)
        reason = (
            f"p={p:.3f} > T2={t2} → REDIRECT to {profile_id} "
            f"(attempts={int(x_ssh[0])}, user={event.username})"
        )

    profile_id = None
    if decision == "redirect":
        profile_id = select_profile(event.username or "", p)
        apply_dnat(event.src_ip or "", profile_id)

    dec = DecisionResult(
        id=uuid.uuid4(),
        ts=datetime.utcnow(),
        decision=decision,
        p=p,
        score=p,
        t1=t1,
        t2=t2,
        model_version=result.get("model_version", "stub"),
        features_hash=hashlib.md5(str(feat).encode()).hexdigest(),
        profile_id=profile_id,
        reason=reason,
    )
    await crud.insert_decision(db, dec)

    logger.info(f"[{event.src_ip}] {reason}")

    if decision in ("alert", "redirect"):
        from modules.alerting import send_alert

        await send_alert(dec, event)


def _handle_non_ssh(event: NormalizedEvent) -> None:
    from modules.alerting import send_non_ssh_alert
    import asyncio

    if (event.channel in ("syscheck", "rootcheck") and event.wazuh_rule_level >= 7) or event.channel == "cowrie":
        asyncio.create_task(send_non_ssh_alert(event))
