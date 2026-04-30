"""
CRUD operations — all async, all append-only for DECISION.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from db.models import Event, Decision, Alert, Whitelist, AuditLog
from schemas.normalized_event import NormalizedEvent
from schemas.decision_result import DecisionResult


async def insert_event(db: AsyncSession, event: NormalizedEvent) -> None:
    db.add(Event(
        id=event.id,
        ts=event.ts,
        src_ip=str(event.src_ip) if event.src_ip else None,
        channel=event.channel,
        event_type=event.event_type,
        username=event.username,
        success=event.success,
        profile_id=event.profile_id,
        wazuh_rule_id=event.wazuh_rule_id,
        wazuh_rule_level=event.wazuh_rule_level,
        ingestion_path=event.ingestion_path,
        syscheck_path=event.syscheck_path,
        syscheck_event=event.syscheck_event,
        syscheck_sha256_after=event.syscheck_sha256_after,
        raw_ref=event.raw_ref,
    ))


async def insert_decision(db: AsyncSession, dec: DecisionResult) -> None:
    db.add(Decision(
        id=dec.id,
        session_id=dec.session_id,
        ts=dec.ts,
        decision=dec.decision,
        p=dec.p,
        score=dec.score,
        t1=dec.t1,
        t2=dec.t2,
        model_version=dec.model_version,
        features_hash=dec.features_hash,
        profile_id=dec.profile_id,
        reason=dec.reason,
    ))


async def get_whitelist(db: AsyncSession) -> list[str]:
    result = await db.execute(select(Whitelist.ip))
    return [str(row[0]) for row in result.all()]


async def append_audit(
    db: AsyncSession, actor: str, action: str,
    before: dict, after: dict
) -> None:
    db.add(AuditLog(actor=actor, action=action, before=before, after=after))
