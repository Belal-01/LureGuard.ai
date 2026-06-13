"""
CRUD operations — all async, all append-only for DECISION.
"""
import uuid
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from db.models import (
    Event,
    Decision,
    Alert,
    Whitelist,
    AuditLog,
    Investigation,
    AgentAction,
    Report,
    Host,
    IpGeolocation,
)
from modules.ip_geo import is_public_ip, lookup_ip
from schemas.normalized_event import NormalizedEvent
from schemas.decision_result import DecisionResult


async def ensure_ip_geolocation(db: AsyncSession, ip: str | None) -> None:
    if not ip or not is_public_ip(ip):
        return
    existing = await db.execute(select(IpGeolocation).where(IpGeolocation.ip == ip))
    if existing.scalar_one_or_none():
        return
    geo = await lookup_ip(ip)
    if not geo:
        return
    db.add(
        IpGeolocation(
            ip=ip,
            country_code=geo["country_code"] or None,
            country_name=geo["country_name"] or None,
            lat=geo["lat"],
            lon=geo["lon"],
            updated_at=datetime.utcnow(),
        )
    )


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
        agent_id=event.agent_id,
        agent_name=event.agent_name,
        agent_ip=str(event.agent_ip) if event.agent_ip else None,
        ingestion_path=event.ingestion_path,
        syscheck_path=event.syscheck_path,
        syscheck_event=event.syscheck_event,
        syscheck_sha256_after=event.syscheck_sha256_after,
        raw_ref=event.raw_ref,
    ))
    await ensure_ip_geolocation(db, str(event.src_ip) if event.src_ip else None)


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


async def list_whitelist_entries(db: AsyncSession) -> list[Whitelist]:
    result = await db.execute(select(Whitelist).order_by(Whitelist.added_at))
    return list(result.scalars().all())


async def add_whitelist_ip(
    db: AsyncSession,
    ip: str,
    *,
    reason: str | None = None,
    added_by: str = "admin",
) -> Whitelist:
    ip = ip.strip()
    existing = await db.get(Whitelist, ip)
    if existing:
        if reason:
            existing.reason = reason
        return existing
    row = Whitelist(ip=ip, reason=reason, added_by=added_by)
    db.add(row)
    return row


async def remove_whitelist_ip(db: AsyncSession, ip: str) -> bool:
    row = await db.get(Whitelist, ip.strip())
    if row is None:
        return False
    await db.delete(row)
    return True


async def append_audit(
    db: AsyncSession, actor: str, action: str,
    before: dict, after: dict
) -> None:
    db.add(AuditLog(actor=actor, action=action, before=before, after=after))


async def create_investigation(
    db: AsyncSession,
    *,
    trigger: str,
    subject: str,
    severity: str | None = None,
) -> Investigation:
    row = Investigation(
        id=uuid.uuid4(),
        trigger=trigger,
        subject=subject,
        status="open",
        severity=severity,
        started_at=datetime.utcnow(),
    )
    db.add(row)
    return row


async def close_investigation(
    db: AsyncSession,
    investigation_id: uuid.UUID,
    *,
    verdict: str,
    confidence: str,
    summary: str,
) -> Investigation | None:
    row = await db.get(Investigation, investigation_id)
    if row is None:
        return None
    row.status = "closed"
    row.verdict = verdict
    row.confidence = confidence
    row.summary = summary
    row.closed_at = datetime.utcnow()
    return row


async def insert_agent_action(
    db: AsyncSession,
    *,
    tool_name: str,
    args: dict | None,
    result_summary: str,
    duration_ms: int,
    investigation_id: uuid.UUID | None = None,
) -> AgentAction:
    row = AgentAction(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        tool_name=tool_name,
        args=args,
        result_summary=result_summary[:4000] if result_summary else None,
        duration_ms=duration_ms,
        ts=datetime.utcnow(),
    )
    db.add(row)
    return row


async def insert_report(
    db: AsyncSession,
    *,
    title: str,
    file_path: str,
    investigation_id: uuid.UUID | None = None,
    fmt: str = "markdown",
) -> Report:
    row = Report(
        id=uuid.uuid4(),
        investigation_id=investigation_id,
        title=title,
        file_path=file_path,
        format=fmt,
        created_at=datetime.utcnow(),
    )
    db.add(row)
    return row


async def upsert_host(
    db: AsyncSession,
    *,
    agent_id: str,
    name: str,
    ip: str | None = None,
    os_name: str | None = None,
    wazuh_status: str | None = None,
    enrolled_by: str = "sync",
) -> Host:
    row = await db.get(Host, agent_id)
    now = datetime.utcnow()
    if row is None:
        row = Host(
            agent_id=agent_id,
            name=name,
            ip=ip,
            os=os_name,
            wazuh_status=wazuh_status,
            enrolled_by=enrolled_by,
            enrolled_at=now,
            last_seen=now,
        )
        db.add(row)
    else:
        row.name = name
        if ip:
            row.ip = ip
        if os_name:
            row.os = os_name
        if wazuh_status:
            row.wazuh_status = wazuh_status
        row.last_seen = now
    return row


async def list_hosts(db: AsyncSession) -> list[Host]:
    result = await db.execute(select(Host).order_by(Host.name))
    return list(result.scalars().all())


async def get_recent_events(
    db: AsyncSession,
    *,
    limit: int = 50,
    min_level: int | None = None,
    channel: str | None = None,
) -> list[Event]:
    q = select(Event).order_by(desc(Event.ts)).limit(limit)
    if min_level is not None:
        q = q.where(Event.wazuh_rule_level >= min_level)
    if channel:
        q = q.where(Event.channel == channel)
    result = await db.execute(q)
    return list(result.scalars().all())


async def get_events_for_ip(
    db: AsyncSession,
    ip: str,
    *,
    limit: int = 100,
) -> list[Event]:
    result = await db.execute(
        select(Event)
        .where(Event.src_ip == ip)
        .order_by(desc(Event.ts))
        .limit(limit)
    )
    return list(result.scalars().all())


async def count_open_investigations(db: AsyncSession) -> int:
    result = await db.execute(
        select(func.count()).select_from(Investigation).where(Investigation.status == "open")
    )
    return int(result.scalar() or 0)
