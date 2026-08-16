"""
Decision Policy — orchestrates the full pipeline for each event.
"""
import asyncio
import hashlib
import uuid
from datetime import datetime, timezone

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import crud
from modules import feature_extractor
from modules.profile_selector import select_profile
from runtime import whitelist as whitelist_cache
from schemas.normalized_event import NormalizedEvent
from schemas.decision_result import DecisionResult


# Alerting (Telegram) must never sit inside the ingest request or the open DB
# transaction (ING-4) — dispatch it as a background task. Keep a strong
# reference so asyncio can't GC the task mid-flight, and log any exception
# that a bare create_task would otherwise swallow as an "unretrieved" warning.
_background_tasks: set[asyncio.Task] = set()


def _dispatch(coro, label: str) -> None:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)

    def _done(t: asyncio.Task) -> None:
        _background_tasks.discard(t)
        exc = t.exception() if not t.cancelled() else None
        if exc is not None:
            logger.error(f"Background alert dispatch failed ({label}): {exc!r}")

    task.add_done_callback(_done)


def _record_decision_metric(decision: str) -> None:
    try:
        from api.metrics_endpoint import decisions_total

        decisions_total.labels(decision=decision).inc()
    except Exception:
        pass


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
    """Clamp a score when the window holds too few events to be an attack.

    ML-8: no longer in the live path. It used to run between the model and the
    operator on SSH, where it could clamp p below T1 on a Wazuh-confirmed brute
    force (our 300s window sees only the events that reached us; Wazuh's rule
    5712 counts 8 in 120s on the host) and silently send nothing. Kept only for
    core/evaluate.py, which reproduces model scoring offline.
    """
    minimum = settings.min_attempts_for_alert
    if attempt_count < minimum:
        return min(p, t1 - 1e-6)
    return p


# Wazuh's own "this matters" line. Rule 5712 escalates here on 8 failures in
# 120s from one source — the correlation f1/f3 were reimplementing. At or above
# it the detection reaches the operator, whatever channel it arrived on and
# whatever our scoring makes of it.
WAZUH_ALERT_LEVEL = 10
FIM_ALERT_LEVEL = 7


def should_alert(event: NormalizedEvent, decision: str | None = None) -> bool:
    """The one place that decides whether an event reaches the operator.

    Every dispatch goes through here. Alerting used to be decided in two
    scattered branches — the SSH classifier path and a channel allow-list — so
    a detection on an unlisted channel alerted nobody (ING-9) and a level-10
    brute force could be vetoed by our own score (ML-8).
    """
    if _is_whitelisted(event):
        # A human decided this source is ours. That outranks every detection.
        return False
    if event.wazuh_rule_level >= WAZUH_ALERT_LEVEL:
        # Rules detect; our scoring does not get a veto.
        return True
    if event.channel in ("syscheck", "rootcheck"):
        return event.wazuh_rule_level >= FIM_ALERT_LEVEL
    if event.channel in ("cowrie", "cowrie_session", "web", "windows"):
        return True
    if event.event_type == "cowrie_session":
        return True
    return decision in ("alert", "redirect")


def _ssh_verdict(event: NormalizedEvent, attempts: int) -> float:
    """Rule-driven SSH score — the classifier no longer sits in this path.

    Wazuh rule 5712 escalates to level 10 on 8 failures in 120s from one source;
    our own rolling window counts the same failures over `window_seconds` and is
    what catches direct-ingest events that carry no rule level. Either is a
    confirmed brute force, so it scores 1.0 rather than a probability: this is a
    rule that fired, not a guess.
    """
    confirmed = (
        event.wazuh_rule_level >= WAZUH_ALERT_LEVEL
        or attempts >= settings.min_attempts_for_alert
    )
    return 1.0 if confirmed else 0.0


async def process_event(event: NormalizedEvent, db: AsyncSession) -> None:
    await crud.insert_event(db, event)

    if event.channel != "sshd" or event.event_type not in ("auth_failed", "auth_success"):
        _handle_non_ssh(event)
        return

    x_ssh = feature_extractor.extract_ssh_features(event)
    attempts = int(x_ssh[0])
    t1, t2 = settings.thresholds.t1, settings.thresholds.t2

    if _is_whitelisted(event):
        p, decision, profile_id = 0.0, "allow", None
        reason = f"whitelisted IP {event.src_ip} → ALLOW"
    else:
        p = _ssh_verdict(event, attempts)
        decision = decide(p, t1, t2)
        profile_id = None
        evidence = (
            f"rule={event.wazuh_rule_id} level={event.wazuh_rule_level}, "
            f"attempts={attempts}/{settings.window_seconds}s, user={event.username}"
        )
        if decision == "allow":
            reason = f"no rule matched → ALLOW ({evidence})"
        elif decision == "alert":
            reason = f"rule match → ALERT ({evidence})"
        else:
            # Recommendation only. Containment is human-gated via the MCP
            # recommend_block_ip -> confirm_block_ip path, which executes over SSH
            # on the enrolled host and verifies the result. Core does not enforce.
            profile_id = select_profile(event.username or "", p)
            reason = (
                f"rule match → RECOMMEND redirect to {profile_id}, not applied "
                f"({evidence})"
            )

    dec = DecisionResult(
        id=uuid.uuid4(),
        event_id=event.id,
        ts=datetime.utcnow(),
        decision=decision,
        p=p,
        score=p,
        t1=t1,
        t2=t2,
        model_version="rules-wazuh",
        features_hash=hashlib.md5(x_ssh.tobytes()).hexdigest(),
        profile_id=profile_id,
        reason=reason,
    )
    await crud.insert_decision(db, dec)
    _record_decision_metric(decision)

    logger.info(f"[{event.src_ip}] {reason}")

    if should_alert(event, decision):
        from modules.alerting import send_alert

        _dispatch(send_alert(dec, event), label=f"send_alert[{event.src_ip}]")


def _handle_non_ssh(event: NormalizedEvent) -> None:
    if should_alert(event):
        from modules.alerting import send_non_ssh_alert

        _dispatch(send_non_ssh_alert(event), label=f"send_non_ssh_alert[{event.channel}]")
