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
    agent_id = Column(String(16))
    agent_name = Column(String(128))
    agent_ip = Column(INET)
    ingestion_path = Column(String(16), default="wazuh")
    syscheck_path = Column(Text)
    syscheck_event = Column(String(16))
    syscheck_sha256_after = Column(String(64))
    raw_ref = Column(Text)

    __table_args__ = (
        Index("ix_events_src_ip_ts", "src_ip", "ts"),
        Index("ix_events_agent_id_ts", "agent_id", "ts"),
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


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    trigger = Column(String(32), nullable=False)  # human | wazuh_event
    subject = Column(String(256), nullable=False)
    status = Column(String(16), nullable=False, default="open")  # open | closed
    verdict = Column(String(32))  # true_positive | false_positive | undetermined
    confidence = Column(String(16))  # confirmed | high | medium | low
    severity = Column(String(8))  # P1 | P2 | P3 | P4
    detection_source = Column(String(64))  # wazuh | human | scheduled
    asset_criticality = Column(String(16))  # critical | high | medium | low
    mttd_seconds = Column(Integer)
    kill_chain_summary = Column(Text)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    closed_at = Column(DateTime)
    summary = Column(Text)

    actions = relationship("AgentAction", back_populates="investigation")
    reports = relationship("Report", back_populates="investigation")
    findings = relationship("Finding", back_populates="investigation")
    timeline_events = relationship("TimelineEvent", back_populates="investigation")
    iocs = relationship("Ioc", back_populates="investigation")

    __table_args__ = (
        Index("ix_investigations_started_at", "started_at"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    evidence_id = Column(String(16), nullable=False)
    finding = Column(Text, nullable=False)
    citation = Column(Text, nullable=False)
    mitre_technique = Column(String(32))
    mitre_tactic = Column(String(64))
    severity = Column(String(8))
    verdict = Column(String(32))
    confidence = Column(String(16))
    ioc_type = Column(String(32))
    ioc_value = Column(Text)
    ts = Column(DateTime, default=datetime.utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_investigation_id", "investigation_id"),
        Index("ix_findings_mitre_technique", "mitre_technique"),
        Index("ix_findings_severity", "severity"),
    )


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    ts_event = Column(DateTime, nullable=False)
    phase = Column(String(32))  # identification | containment | eradication | recovery | lessons
    description = Column(Text, nullable=False)
    source = Column(String(128))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="timeline_events")

    __table_args__ = (
        Index("ix_timeline_events_investigation_id", "investigation_id"),
        Index("ix_timeline_events_ts_event", "ts_event"),
    )


class Ioc(Base):
    __tablename__ = "iocs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    type = Column(String(32), nullable=False)
    value = Column(Text, nullable=False)
    defanged = Column(Text)
    reputation = Column(String(32))
    source = Column(String(64))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="iocs")

    __table_args__ = (
        Index("ix_iocs_investigation_id", "investigation_id"),
        Index("ix_iocs_type", "type"),
    )


class AgentAction(Base):
    __tablename__ = "agent_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id"))
    tool_name = Column(String(128), nullable=False)
    args = Column(JSONB)
    result_summary = Column(Text)
    duration_ms = Column(Integer)
    ts = Column(DateTime, default=datetime.utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="actions")

    __table_args__ = (
        Index("ix_agent_actions_ts", "ts"),
        Index("ix_agent_actions_investigation_id", "investigation_id"),
    )


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id"))
    title = Column(String(256), nullable=False)
    file_path = Column(Text, nullable=False)
    format = Column(String(16), default="markdown")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="reports")


class IpGeolocation(Base):
    __tablename__ = "ip_geolocation"

    ip = Column(INET, primary_key=True)
    country_code = Column(String(2))
    country_name = Column(String(128))
    lat = Column(Float)
    lon = Column(Float)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Host(Base):
    __tablename__ = "hosts"

    agent_id = Column(String(16), primary_key=True)
    name = Column(String(128), nullable=False)
    ip = Column(INET)
    os = Column(String(128))
    wazuh_status = Column(String(32))  # active | disconnected | never_connected | pending
    enrolled_by = Column(String(16), default="manual")  # agent | manual | sync
    enrolled_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime)


class CveFinding(Base):
    __tablename__ = "cve_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(String(16), ForeignKey("hosts.agent_id", ondelete="CASCADE"), nullable=False)
    package_name = Column(String(256), nullable=False)
    package_version = Column(String(128), nullable=False)
    cve_id = Column(String(32), nullable=False)
    severity = Column(String(16), nullable=False)
    cvss = Column(Float)
    fix_version = Column(String(128))
    summary = Column(Text)
    source = Column(String(16), default="osv", nullable=False)
    scanned_at = Column(DateTime, nullable=False)
    actionable = Column(Boolean, default=True, nullable=False)
    service_running = Column(Boolean, default=False, nullable=False)
    on_kev = Column(Boolean, default=False, nullable=False)
    priority_score = Column(Integer)

    __table_args__ = (
        Index("ix_cve_findings_agent_id", "agent_id"),
        Index("ix_cve_findings_severity", "severity"),
        Index("ix_cve_findings_scanned_at", "scanned_at"),
        Index("ix_cve_findings_actionable", "actionable"),
        Index("ix_cve_findings_priority_score", "priority_score"),
    )


class ExposureFinding(Base):
    __tablename__ = "exposure_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(String(16), ForeignKey("hosts.agent_id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(16), nullable=False)
    process = Column(String(256))
    local_address = Column(String(64))
    state = Column(String(32))
    risk_level = Column(String(16), nullable=False)
    bind_scope = Column(String(32))
    scanned_at = Column(DateTime, nullable=False)

    __table_args__ = (
        Index("ix_exposure_findings_agent_id", "agent_id"),
        Index("ix_exposure_findings_risk_level", "risk_level"),
    )


class DetectionCoverage(Base):
    __tablename__ = "detection_coverage"

    agent_id = Column(String(16), ForeignKey("hosts.agent_id", ondelete="CASCADE"), primary_key=True)
    fim_enabled = Column(Boolean, default=False, nullable=False)
    rootcheck_enabled = Column(Boolean, default=False, nullable=False)
    alerts_24h = Column(Integer, default=0, nullable=False)
    rules_firing = Column(JSONB)
    silent_rules_count = Column(Integer, default=0, nullable=False)
    channels_active = Column(JSONB)
    events_last_at = Column(DateTime)
    rules_firing_count = Column(Integer, default=0, nullable=False)
    scanned_at = Column(DateTime, nullable=False)

    __table_args__ = (Index("ix_detection_coverage_scanned_at", "scanned_at"),)
