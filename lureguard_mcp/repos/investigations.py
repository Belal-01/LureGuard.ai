"""Investigation lifecycle and reports."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from typing import Any

import psycopg2
import psycopg2.extras

from lureguard_mcp.config import REPORTS_DIR
from lureguard_mcp.presentation import infer_attack_phases, row_to_dict, shape_event_row
from lureguard_mcp.report_storage import write_report_markdown
from lureguard_mcp.repos.connection import get_conn
from lureguard_mcp.secrets import redact_mapping


def _row_to_dict(row: dict[str, Any]) -> dict[str, Any]:
    return shape_event_row(row_to_dict(row))


def _infer_attack_phases(events: list[dict]) -> list[str]:
    return infer_attack_phases(events)

def open_investigation(
    *,
    trigger: str,
    subject: str,
    severity: str | None = None,
    detection_source: str | None = None,
    asset_criticality: str | None = None,
) -> dict:
    inv_id = str(uuid.uuid4())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO investigations
                    (id, trigger, subject, status, severity, detection_source,
                     asset_criticality, started_at)
                VALUES (%s, %s, %s, 'open', %s, %s, %s, %s)
                RETURNING id, trigger, subject, status, severity, detection_source,
                          asset_criticality, started_at
                """,
                (
                    inv_id,
                    trigger,
                    subject,
                    severity,
                    detection_source,
                    asset_criticality,
                    datetime.utcnow(),
                ),
            )
            row = cur.fetchone()
    return {
        "id": str(row[0]),
        "trigger": row[1],
        "subject": row[2],
        "status": row[3],
        "severity": row[4],
        "detection_source": row[5],
        "asset_criticality": row[6],
        "started_at": row[7].isoformat(),
    }



def _next_evidence_id(cur: Any, investigation_id: str) -> str:
    cur.execute(
        "SELECT count(*) FROM findings WHERE investigation_id = %s",
        (investigation_id,),
    )
    row = cur.fetchone()
    count = int(row[0]) if row else 0
    return f"E{count + 1:02d}"



def record_finding(
    investigation_id: str,
    finding: str,
    citation: str,
    *,
    mitre_technique: str | None = None,
    mitre_tactic: str | None = None,
    severity: str | None = None,
    verdict: str | None = None,
    confidence: str | None = None,
    ioc_type: str | None = None,
    ioc_value: str | None = None,
) -> dict:
    summary = f"Finding: {finding}\nCitation: {citation}"
    finding_id = str(uuid.uuid4())
    with get_conn() as conn:
        with conn.cursor() as cur:
            evidence_id = _next_evidence_id(cur, investigation_id)
            cur.execute(
                """
                INSERT INTO findings (
                    id, investigation_id, evidence_id, finding, citation,
                    mitre_technique, mitre_tactic, severity, verdict, confidence,
                    ioc_type, ioc_value, ts
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    finding_id,
                    investigation_id,
                    evidence_id,
                    finding,
                    citation,
                    mitre_technique,
                    mitre_tactic,
                    severity,
                    verdict,
                    confidence,
                    ioc_type,
                    ioc_value,
                    datetime.utcnow(),
                ),
            )
            if ioc_type and ioc_value:
                from lureguard_mcp.enrichment import defang_indicator

                cur.execute(
                    """
                    INSERT INTO iocs (
                        id, investigation_id, type, value, defanged, source, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()),
                        investigation_id,
                        ioc_type,
                        ioc_value,
                        defang_indicator(ioc_value, ioc_type),
                        "record_finding",
                        datetime.utcnow(),
                    ),
                )
            cur.execute(
                """
                INSERT INTO agent_actions
                    (id, investigation_id, tool_name, args, result_summary, duration_ms, ts)
                VALUES (%s, %s, 'record_finding', %s, %s, 0, %s)
                """,
                (
                    str(uuid.uuid4()),
                    investigation_id,
                    json.dumps(
                        {
                            "finding": finding,
                            "citation": citation,
                            "evidence_id": evidence_id,
                            "mitre_technique": mitre_technique,
                            "mitre_tactic": mitre_tactic,
                            "severity": severity,
                            "verdict": verdict,
                            "confidence": confidence,
                            "ioc_type": ioc_type,
                            "ioc_value": ioc_value,
                        }
                    ),
                    summary[:4000],
                    datetime.utcnow(),
                ),
            )
    return {
        "recorded": True,
        "investigation_id": investigation_id,
        "evidence_id": evidence_id,
        "finding_id": finding_id,
    }



def add_timeline_event(
    investigation_id: str,
    *,
    ts_event: datetime,
    description: str,
    phase: str | None = None,
    source: str | None = None,
) -> dict:
    event_id = str(uuid.uuid4())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO timeline_events (
                    id, investigation_id, ts_event, phase, description, source, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    event_id,
                    investigation_id,
                    ts_event,
                    phase,
                    description,
                    source,
                    datetime.utcnow(),
                ),
            )
    return {
        "recorded": True,
        "investigation_id": investigation_id,
        "timeline_event_id": event_id,
        "ts_event": ts_event.isoformat(),
    }



def close_investigation_db(
    investigation_id: str,
    *,
    verdict: str,
    confidence: str,
    summary: str,
    detection_source: str | None = None,
    asset_criticality: str | None = None,
    mttd_seconds: int | None = None,
    kill_chain_summary: str | None = None,
) -> dict | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE investigations
                SET status = 'closed', verdict = %s, confidence = %s,
                    summary = %s, closed_at = %s,
                    detection_source = COALESCE(%s, detection_source),
                    asset_criticality = COALESCE(%s, asset_criticality),
                    mttd_seconds = COALESCE(%s, mttd_seconds),
                    kill_chain_summary = COALESCE(%s, kill_chain_summary)
                WHERE id = %s
                RETURNING id, status, verdict, confidence, closed_at,
                          detection_source, asset_criticality, mttd_seconds, kill_chain_summary
                """,
                (
                    verdict,
                    confidence,
                    summary,
                    datetime.utcnow(),
                    detection_source,
                    asset_criticality,
                    mttd_seconds,
                    kill_chain_summary,
                    investigation_id,
                ),
            )
            row = cur.fetchone()
    if not row:
        return None
    return {
        "id": str(row[0]),
        "status": row[1],
        "verdict": row[2],
        "confidence": row[3],
        "closed_at": row[4].isoformat() if row[4] else None,
        "detection_source": row[5],
        "asset_criticality": row[6],
        "mttd_seconds": row[7],
        "kill_chain_summary": row[8],
    }



def get_investigation_findings_db(investigation_id: str) -> list[dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT evidence_id, finding, citation, mitre_technique, mitre_tactic,
                       severity, verdict, confidence, ioc_type, ioc_value, ts
                FROM findings
                WHERE investigation_id = %s
                ORDER BY ts ASC
                """,
                (investigation_id,),
            )
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]



def get_investigation_timeline_db(investigation_id: str) -> list[dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT ts_event, phase, description, source, created_at
                FROM timeline_events
                WHERE investigation_id = %s
                ORDER BY ts_event ASC
                """,
                (investigation_id,),
            )
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]



def get_investigation_iocs_db(investigation_id: str) -> list[dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT type, value, defanged, reputation, source, created_at
                FROM iocs
                WHERE investigation_id = %s
                ORDER BY created_at ASC
                """,
                (investigation_id,),
            )
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]



def save_report_db(
    *,
    title: str,
    markdown: str,
    investigation_id: str | None,
) -> dict:
    path = write_report_markdown(title=title, markdown=markdown)
    report_id = str(uuid.uuid4())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reports (id, investigation_id, title, file_path, format, created_at)
                VALUES (%s, %s, %s, %s, 'markdown', %s)
                """,
                (
                    report_id,
                    investigation_id,
                    title,
                    str(path.relative_to(REPORTS_DIR.parent)),
                    datetime.utcnow(),
                ),
            )
    return {"id": report_id, "title": title, "file_path": str(path)}


