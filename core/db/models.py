"""
SQLAlchemy ORM models — 7 tables matching §3.10.1 of the SRS.
"""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, Float,
    DateTime, Text, ForeignKey, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ts = Column(DateTime, default=datetime.utcnow, nullable=False)
    src_ip = Column(INET)
    src_port = Column(Integer)
    channel = Column(String(32), nullable=False)      # sshd|syscheck|rootcheck|cowrie
    event_type = Column(String(64), nullable=False)
    username = Column(String(128))
    success = Column(Boolean, default=False)
    profile_id = Column(String(32))                   # dev-server|db-server|null
    wazuh_rule_id = Column(Integer)
    wazuh_rule_level = Column(Integer)
    ingestion_path = Column(String(16), default="wazuh")
    syscheck_path = Column(Text)
    syscheck_event = Column(String(16))
    syscheck_sha256_after = Column(String(64))
    raw_ref = Column(Text)

    __table_args__ = (
        Index("ix_events_src_ip_ts", "src_ip", "ts"),
    )


class Session(Base):
    __tablename__ = "sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    src_ip = Column(INET)
    profile_id = Column(String(32))
    opened_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime)
    event_count = Column(Integer, default=0)
    p = Column(Float)

    decisions = relationship("Decision", back_populates="session")
    summary = relationship("Summary", back_populates="session", uselist=False)


class Decision(Base):
    __tablename__ = "decisions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id"))
    ts = Column(DateTime, default=datetime.utcnow, nullable=False)
    decision = Column(String(16), nullable=False)     # allow|alert|redirect
    p = Column(Float, nullable=False)
    score = Column(Float, nullable=False)
    t1 = Column(Float)
    t2 = Column(Float)
    model_version = Column(String(32))
    features_hash = Column(String(64))
    profile_id = Column(String(32))
    reason = Column(Text)

    session = relationship("Session", back_populates="decisions")
    alerts = relationship("Alert", back_populates="decision")

    __table_args__ = (
        Index("ix_decisions_ts", "ts"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    decision_id = Column(UUID(as_uuid=True), ForeignKey("decisions.id"))
    ts = Column(DateTime, default=datetime.utcnow)
    category = Column(String(16))                     # SSH|FIM|ROOTKIT
    payload = Column(JSONB)
    sent = Column(Boolean, default=False)

    decision = relationship("Decision", back_populates="alerts")


class Summary(Base):
    __tablename__ = "summaries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id"))
    provider = Column(String(32))
    model = Column(String(64))
    prompt_hash = Column(String(64))
    summary_text = Column(Text)
    tokens_in = Column(Integer, default=0)
    tokens_out = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    status = Column(String(16))                       # OK|DISABLED|FAILED
    error = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("Session", back_populates="summary")


class Whitelist(Base):
    __tablename__ = "whitelist"

    ip = Column(INET, primary_key=True)
    reason = Column(Text)
    added_by = Column(String(64))
    added_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ts = Column(DateTime, default=datetime.utcnow)
    actor = Column(String(64))
    action = Column(String(128))
    before = Column(JSONB)
    after = Column(JSONB)
