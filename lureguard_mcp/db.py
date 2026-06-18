"""Sync Postgres access for MCP tools."""

from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Iterator

import psycopg2
import psycopg2.extras

from lureguard_mcp.config import REPORTS_DIR, database_url_sync


@contextmanager
def get_conn() -> Iterator[Any]:
    conn = psycopg2.connect(database_url_sync())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _row_to_dict(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in row.items():
        if hasattr(val, "isoformat"):
            out[key] = val.isoformat()
        else:
            out[key] = str(val) if val is not None and key in ("src_ip", "ip") else val
    return out


def _agent_event_filter(agent_id: str, agent_ip: str | None) -> tuple[str, list[Any]]:
    """Match events by agent_id with IP fallbacks for legacy rows."""
    params: list[Any] = [agent_id]
    clause = "(agent_id = %s"
    if agent_ip:
        clause += " OR (agent_id IS NULL AND (agent_ip = %s::inet OR src_ip = %s::inet))"
        params.extend([agent_ip, agent_ip])
    clause += ")"
    return clause, params


def log_agent_action(
    *,
    tool_name: str,
    args: dict | None,
    result_summary: str,
    duration_ms: int,
    investigation_id: str | None,
) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO agent_actions
                    (id, investigation_id, tool_name, args, result_summary, duration_ms, ts)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    investigation_id,
                    tool_name,
                    json.dumps(args or {}),
                    (result_summary or "")[:4000],
                    duration_ms,
                    datetime.utcnow(),
                ),
            )


def get_recent_alerts(
    *,
    limit: int = 50,
    min_level: int | None = None,
    channel: str | None = None,
) -> list[dict]:
    clauses = ["1=1"]
    params: list[Any] = []
    if min_level is not None:
        clauses.append("wazuh_rule_level >= %s")
        params.append(min_level)
    if channel:
        clauses.append("channel = %s")
        params.append(channel)
    params.append(limit)
    sql = f"""
        SELECT id, ts, host(src_ip) AS src_ip, channel, event_type, username,
               wazuh_rule_id, wazuh_rule_level, profile_id
        FROM events
        WHERE {' AND '.join(clauses)}
        ORDER BY ts DESC
        LIMIT %s
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]


def get_alerts_for_ip(ip: str, *, limit: int = 100) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, ts, host(src_ip) AS src_ip, channel, event_type, username,
                       wazuh_rule_id, wazuh_rule_level, syscheck_path, raw_ref
                FROM events
                WHERE src_ip = %s::inet
                ORDER BY ts DESC
                LIMIT %s
                """,
                (ip, limit),
            )
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]


def get_event_timeline(ip: str, *, window_hours: int = 24) -> list[dict]:
    since = datetime.utcnow() - timedelta(hours=window_hours)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT ts, channel, event_type, username, wazuh_rule_level, wazuh_rule_id,
                       syscheck_path, syscheck_event
                FROM events
                WHERE src_ip = %s::inet AND ts >= %s
                ORDER BY ts ASC
                """,
                (ip, since),
            )
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]


def search_events(
    *,
    ip: str | None = None,
    channel: str | None = None,
    min_level: int | None = None,
    username: str | None = None,
    limit: int = 100,
) -> list[dict]:
    clauses = ["1=1"]
    params: list[Any] = []
    if ip:
        clauses.append("src_ip = %s::inet")
        params.append(ip)
    if channel:
        clauses.append("channel = %s")
        params.append(channel)
    if min_level is not None:
        clauses.append("wazuh_rule_level >= %s")
        params.append(min_level)
    if username:
        clauses.append("username ILIKE %s")
        params.append(f"%{username}%")
    params.append(limit)
    sql = f"""
        SELECT id, ts, host(src_ip) AS src_ip, channel, event_type, username,
               wazuh_rule_level, wazuh_rule_id
        FROM events
        WHERE {' AND '.join(clauses)}
        ORDER BY ts DESC
        LIMIT %s
    """
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]


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
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    slug = "".join(c if c.isalnum() else "-" for c in title.lower())[:40].strip("-")
    date_prefix = datetime.utcnow().strftime("%Y%m%d")
    filename = f"{date_prefix}-{slug or 'report'}.md"
    path = REPORTS_DIR / filename
    path.write_text(markdown, encoding="utf-8")
    report_id = str(uuid.uuid4())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reports (id, investigation_id, title, file_path, format, created_at)
                VALUES (%s, %s, %s, %s, 'markdown', %s)
                """,
                (report_id, investigation_id, title, str(path.relative_to(REPORTS_DIR.parent)), datetime.utcnow()),
            )
    return {"id": report_id, "title": title, "file_path": str(path)}


def upsert_host_db(
    *,
    agent_id: str,
    name: str,
    ip: str | None = None,
    os_name: str | None = None,
    wazuh_status: str | None = None,
    enrolled_by: str = "agent",
) -> None:
    now = datetime.utcnow()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO hosts (agent_id, name, ip, os, wazuh_status, enrolled_by, enrolled_at, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (agent_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    ip = COALESCE(EXCLUDED.ip, hosts.ip),
                    os = COALESCE(EXCLUDED.os, hosts.os),
                    wazuh_status = COALESCE(EXCLUDED.wazuh_status, hosts.wazuh_status),
                    last_seen = EXCLUDED.last_seen
                """,
                (agent_id, name, ip, os_name, wazuh_status, enrolled_by, now, now),
            )


def list_hosts_db() -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT agent_id, name, host(ip) AS ip, os, wazuh_status,
                       enrolled_by, enrolled_at, last_seen
                FROM hosts ORDER BY name
                """
            )
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]


def replace_agent_cve_findings_db(
    *,
    agent_id: str,
    findings: list[dict[str, Any]],
    scanned_at: datetime,
) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM cve_findings WHERE agent_id = %s", (agent_id,))
            for item in findings:
                cur.execute(
                    """
                    INSERT INTO cve_findings (
                        id, agent_id, package_name, package_version, cve_id,
                        severity, cvss, fix_version, summary, source, scanned_at,
                        actionable, service_running, on_kev, priority_score, epss_score
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()),
                        agent_id,
                        item["package_name"],
                        item["package_version"],
                        item["cve_id"],
                        item.get("severity", "unknown"),
                        item.get("cvss"),
                        item.get("fix_version"),
                        item.get("summary"),
                        item.get("source", "osv"),
                        scanned_at,
                        bool(item.get("actionable", True)),
                        bool(item.get("service_running", False)),
                        bool(item.get("on_kev", False)),
                        item.get("priority_score"),
                        item.get("epss_score"),
                    ),
                )
    return len(findings)


def get_agent_cve_findings_db(
    agent_id: str,
    *,
    severity: str | None = None,
    actionable_only: bool = True,
    limit: int = 500,
) -> list[dict[str, Any]]:
    sql = """
        SELECT agent_id, package_name, package_version, cve_id, severity,
               cvss, fix_version, summary, source, scanned_at,
               actionable, service_running, on_kev, priority_score, epss_score
        FROM cve_findings
        WHERE agent_id = %s
    """
    params: list[Any] = [agent_id]
    if actionable_only:
        sql += " AND actionable = true"
    if severity:
        sql += " AND severity = %s"
        params.append(severity.lower())
    sql += " ORDER BY priority_score DESC NULLS LAST, cvss DESC NULLS LAST, cve_id LIMIT %s"
    params.append(limit)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]


def get_agent_cve_counts_db(agent_id: str, *, actionable_only: bool = True) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    sql = """
        SELECT severity, count(*) FROM cve_findings
        WHERE agent_id = %s
    """
    params: list[Any] = [agent_id]
    if actionable_only:
        sql += " AND actionable = true"
    sql += " GROUP BY severity"
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            for sev, cnt in cur.fetchall():
                key = str(sev).lower()
                if key not in counts:
                    key = "unknown"
                counts[key] = int(cnt)
    return counts


def get_agent_cve_last_scan_db(agent_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT max(scanned_at) FROM cve_findings WHERE agent_id = %s",
                (agent_id,),
            )
            row = cur.fetchone()
            if row and row[0]:
                return row[0].isoformat()
    return None


def get_fleet_cve_summary_db() -> dict[str, Any]:
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    fleet: list[dict[str, Any]] = []
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT h.agent_id, h.name, host(h.ip) AS ip,
                       c.severity,
                       count(c.id) FILTER (WHERE c.actionable = true) AS cnt,
                       max(c.scanned_at) AS scanned_at
                FROM hosts h
                LEFT JOIN cve_findings c ON c.agent_id = h.agent_id
                WHERE h.agent_id != '000'
                GROUP BY h.agent_id, h.name, h.ip, c.severity
                ORDER BY h.name
                """
            )
            rows = cur.fetchall()

    by_agent: dict[str, dict[str, Any]] = {}
    for row in rows:
        aid = str(row["agent_id"])
        if aid not in by_agent:
            by_agent[aid] = {
                "agent_id": aid,
                "name": row["name"],
                "ip": str(row["ip"]) if row["ip"] else "",
                "counts": {k: 0 for k in totals},
                "scanned_at": None,
                "error": None,
            }
        sev = str(row["severity"] or "unknown").lower()
        cnt = int(row["cnt"] or 0)
        if row["scanned_at"]:
            scanned = row["scanned_at"].isoformat()
            prev = by_agent[aid].get("scanned_at")
            if not prev or scanned > prev:
                by_agent[aid]["scanned_at"] = scanned
        if row["severity"] is None:
            continue
        if sev not in by_agent[aid]["counts"]:
            sev = "unknown"
        by_agent[aid]["counts"][sev] += cnt
        totals[sev] += cnt

    for entry in by_agent.values():
        entry["total"] = sum(entry["counts"].values())
        if entry["scanned_at"] is None:
            entry["error"] = "not scanned — run scan_agent_vulnerabilities"
        fleet.append(entry)

    fleet.sort(key=lambda x: x.get("name") or "")
    return {
        "source": "postgres+osv",
        "fleet": fleet,
        "totals_by_severity": totals,
        "total_cves": sum(totals.values()),
    }


def replace_agent_exposure_findings_db(
    *,
    agent_id: str,
    findings: list[dict[str, Any]],
    scanned_at: datetime,
) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM exposure_findings WHERE agent_id = %s", (agent_id,))
            rows = findings if findings else [
                {
                    "port": 0,
                    "protocol": "none",
                    "process": None,
                    "local_address": None,
                    "state": "none",
                    "risk_level": "info",
                }
            ]
            for item in rows:
                cur.execute(
                    """
                    INSERT INTO exposure_findings (
                        id, agent_id, port, protocol, process, local_address,
                        state, risk_level, bind_scope, scanned_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()),
                        agent_id,
                        int(item["port"]),
                        item["protocol"],
                        item.get("process"),
                        item.get("local_address"),
                        item.get("state"),
                        item.get("risk_level", "info"),
                        item.get("bind_scope"),
                        scanned_at,
                    ),
                )
    return len(findings)


def get_agent_exposure_findings_db(
    agent_id: str,
    *,
    risk_level: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    sql = """
        SELECT agent_id, port, protocol, process, local_address, state,
               risk_level, bind_scope, scanned_at
        FROM exposure_findings
        WHERE agent_id = %s AND port > 0
    """
    params: list[Any] = [agent_id]
    if risk_level:
        sql += " AND risk_level = %s"
        params.append(risk_level.lower())
    sql += """
        ORDER BY CASE risk_level
        WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
        WHEN 'low' THEN 4 ELSE 5 END, port LIMIT %s"""
    params.append(limit)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]


def get_agent_exposure_counts_db(agent_id: str) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT risk_level, count(*) FROM exposure_findings
                WHERE agent_id = %s AND port > 0 GROUP BY risk_level
                """,
                (agent_id,),
            )
            for level, cnt in cur.fetchall():
                key = str(level).lower()
                if key not in counts:
                    key = "info"
                counts[key] = int(cnt)
    return counts


def get_agent_exposure_last_scan_db(agent_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT max(scanned_at) FROM exposure_findings WHERE agent_id = %s",
                (agent_id,),
            )
            row = cur.fetchone()
            if row and row[0]:
                return row[0].isoformat()
    return None


def get_fleet_exposure_summary_db() -> dict[str, Any]:
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    fleet: list[dict[str, Any]] = []
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT h.agent_id, h.name, host(h.ip) AS ip,
                       e.risk_level, count(e.id) AS cnt, max(e.scanned_at) AS scanned_at
                FROM hosts h
                LEFT JOIN exposure_findings e ON e.agent_id = h.agent_id AND e.port > 0
                WHERE h.agent_id != '000'
                GROUP BY h.agent_id, h.name, h.ip, e.risk_level
                ORDER BY h.name
                """
            )
            rows = cur.fetchall()

    by_agent: dict[str, dict[str, Any]] = {}
    for row in rows:
        aid = str(row["agent_id"])
        if aid not in by_agent:
            by_agent[aid] = {
                "agent_id": aid,
                "name": row["name"],
                "ip": str(row["ip"]) if row["ip"] else "",
                "counts": {k: 0 for k in totals},
                "scanned_at": None,
                "error": None,
            }
        if row["scanned_at"]:
            scanned = row["scanned_at"].isoformat()
            prev = by_agent[aid].get("scanned_at")
            if not prev or scanned > prev:
                by_agent[aid]["scanned_at"] = scanned
        if row["risk_level"] is None:
            continue
        level = str(row["risk_level"]).lower()
        cnt = int(row["cnt"] or 0)
        if level not in by_agent[aid]["counts"]:
            level = "info"
        by_agent[aid]["counts"][level] += cnt
        totals[level] += cnt

    for entry in by_agent.values():
        entry["total"] = sum(entry["counts"].values())
        if entry["scanned_at"] is None:
            entry["error"] = "not scanned — run trigger_posture_scan"
        fleet.append(entry)

    fleet.sort(key=lambda x: x.get("name") or "")
    return {
        "source": "postgres+syscollector",
        "fleet": fleet,
        "totals_by_risk": totals,
        "total_exposures": sum(totals.values()),
    }


def upsert_detection_coverage_db(
    *,
    agent_id: str,
    fim_enabled: bool,
    rootcheck_enabled: bool,
    alerts_24h: int,
    rules_firing: list[dict[str, Any]] | None,
    rules_firing_count: int,
    events_last_at: datetime | None,
    channels_active: dict[str, int] | None,
    scanned_at: datetime,
) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO detection_coverage (
                    agent_id, fim_enabled, rootcheck_enabled, alerts_24h,
                    rules_firing, silent_rules_count, rules_firing_count,
                    events_last_at, channels_active, scanned_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (agent_id) DO UPDATE SET
                    fim_enabled = EXCLUDED.fim_enabled,
                    rootcheck_enabled = EXCLUDED.rootcheck_enabled,
                    alerts_24h = EXCLUDED.alerts_24h,
                    rules_firing = EXCLUDED.rules_firing,
                    silent_rules_count = EXCLUDED.rules_firing_count,
                    rules_firing_count = EXCLUDED.rules_firing_count,
                    events_last_at = EXCLUDED.events_last_at,
                    channels_active = EXCLUDED.channels_active,
                    scanned_at = EXCLUDED.scanned_at
                """,
                (
                    agent_id,
                    fim_enabled,
                    rootcheck_enabled,
                    alerts_24h,
                    json.dumps(rules_firing) if rules_firing is not None else None,
                    rules_firing_count,
                    rules_firing_count,
                    events_last_at,
                    json.dumps(channels_active) if channels_active is not None else None,
                    scanned_at,
                ),
            )


def get_agent_detection_coverage_db(agent_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT agent_id, fim_enabled, rootcheck_enabled, alerts_24h,
                       rules_firing, rules_firing_count, events_last_at,
                       channels_active, scanned_at
                FROM detection_coverage
                WHERE agent_id = %s
                """,
                (agent_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return _row_to_dict(dict(row))


def get_fleet_detection_coverage_db() -> dict[str, Any]:
    fleet: list[dict[str, Any]] = []
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT h.agent_id, h.name, host(h.ip) AS ip,
                       d.fim_enabled, d.rootcheck_enabled, d.alerts_24h,
                       d.rules_firing_count, d.events_last_at, d.channels_active, d.scanned_at
                FROM hosts h
                LEFT JOIN detection_coverage d ON d.agent_id = h.agent_id
                WHERE h.agent_id != '000'
                ORDER BY h.name
                """
            )
            rows = cur.fetchall()

    totals = {"fim_enabled": 0, "rootcheck_enabled": 0, "alerts_24h": 0}
    for row in rows:
        entry = {
            "agent_id": str(row["agent_id"]),
            "name": row["name"],
            "ip": str(row["ip"]) if row["ip"] else "",
            "fim_enabled": bool(row["fim_enabled"]) if row["scanned_at"] else None,
            "rootcheck_enabled": bool(row["rootcheck_enabled"]) if row["scanned_at"] else None,
            "alerts_24h": int(row["alerts_24h"] or 0) if row["scanned_at"] else None,
            "rules_firing_count": int(row["rules_firing_count"] or 0) if row["scanned_at"] else None,
            "events_last_at": row["events_last_at"].isoformat() if row.get("events_last_at") else None,
            "channels_active": row["channels_active"],
            "scanned_at": row["scanned_at"].isoformat() if row["scanned_at"] else None,
            "error": None if row["scanned_at"] else "not scanned — run trigger_posture_scan",
        }
        if row["scanned_at"]:
            if entry["fim_enabled"]:
                totals["fim_enabled"] += 1
            if entry["rootcheck_enabled"]:
                totals["rootcheck_enabled"] += 1
            totals["alerts_24h"] += int(entry["alerts_24h"] or 0)
        fleet.append(entry)

    return {"source": "postgres+events", "fleet": fleet, "totals": totals}


def count_agent_alerts_24h_db(agent_id: str, agent_ip: str | None = None) -> int:
    since = datetime.utcnow() - timedelta(hours=24)
    clause, params = _agent_event_filter(agent_id, agent_ip)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT count(*) FROM events WHERE ts >= %s AND {clause}",
                [since, *params],
            )
            row = cur.fetchone()
            return int(row[0]) if row else 0


def get_agent_events_last_at_db(agent_id: str, agent_ip: str | None = None) -> datetime | None:
    clause, params = _agent_event_filter(agent_id, agent_ip)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT max(ts) FROM events WHERE {clause}",
                params,
            )
            row = cur.fetchone()
            return row[0] if row and row[0] else None


def get_agent_rules_firing_24h_db(
    agent_id: str,
    agent_ip: str | None = None,
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    since = datetime.utcnow() - timedelta(hours=24)
    clause, params = _agent_event_filter(agent_id, agent_ip)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT wazuh_rule_id AS rule_id, max(wazuh_rule_level) AS level,
                       count(*) AS count
                FROM events
                WHERE ts >= %s AND {clause} AND wazuh_rule_id IS NOT NULL
                GROUP BY wazuh_rule_id
                ORDER BY count DESC
                LIMIT %s
                """,
                [since, *params, limit],
            )
            return [dict(r) for r in cur.fetchall()]


def get_agent_channels_active_24h_db(
    agent_id: str,
    agent_ip: str | None = None,
) -> dict[str, int]:
    since = datetime.utcnow() - timedelta(hours=24)
    clause, params = _agent_event_filter(agent_id, agent_ip)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT channel, count(*) FROM events
                WHERE ts >= %s AND {clause}
                GROUP BY channel
                """,
                [since, *params],
            )
            return {str(ch): int(cnt) for ch, cnt in cur.fetchall()}


def get_host_ip_db(agent_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT host(ip) FROM hosts WHERE agent_id = %s", (agent_id,))
            row = cur.fetchone()
            return str(row[0]) if row and row[0] else None


def get_soc_health_db() -> dict[str, Any]:
    """Fleet ingestion health — event volume and last-seen timestamps."""
    since = datetime.utcnow() - timedelta(hours=24)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT max(ts) AS last_event_at FROM events")
            last_row = cur.fetchone()
            cur.execute("SELECT count(*) AS cnt FROM events WHERE ts >= %s", (since,))
            vol_row = cur.fetchone()
            cur.execute(
                """
                SELECT agent_id, max(ts) AS last_at, count(*) AS events_24h
                FROM events
                WHERE ts >= %s AND agent_id IS NOT NULL
                GROUP BY agent_id
                ORDER BY agent_id
                """,
                (since,),
            )
            by_agent = [dict(r) for r in cur.fetchall()]
            cur.execute(
                "SELECT count(*) AS cnt FROM events WHERE ts >= %s AND agent_id IS NULL",
                (since,),
            )
            legacy_row = cur.fetchone()
    return {
        "window_hours": 24,
        "events_24h": int(vol_row["cnt"] or 0) if vol_row else 0,
        "last_event_at": (
            last_row["last_event_at"].isoformat()
            if last_row and last_row.get("last_event_at")
            else None
        ),
        "events_missing_agent_id_24h": int(legacy_row["cnt"] or 0) if legacy_row else 0,
        "agents_with_events_24h": [
            {
                "agent_id": str(r["agent_id"]),
                "events_24h": int(r["events_24h"] or 0),
                "last_at": r["last_at"].isoformat() if r.get("last_at") else None,
            }
            for r in by_agent
        ],
    }


def set_host_eol_os_db(agent_id: str, eol_os: bool) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE hosts SET eol_os = %s WHERE agent_id = %s",
                (eol_os, agent_id),
            )


def get_host_eol_os_db(agent_id: str) -> bool:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT eol_os FROM hosts WHERE agent_id = %s", (agent_id,))
            row = cur.fetchone()
            return bool(row[0]) if row else False


def replace_agent_sca_findings_db(
    *,
    agent_id: str,
    findings: list[dict[str, Any]],
    scanned_at: datetime,
) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sca_findings WHERE agent_id = %s", (agent_id,))
            rows = findings if findings else [
                {
                    "policy_id": "none",
                    "policy_name": None,
                    "check_id": "none",
                    "title": None,
                    "result": "notapplicable",
                    "compliance": None,
                    "remediation": None,
                }
            ]
            for item in rows:
                cur.execute(
                    """
                    INSERT INTO sca_findings (
                        id, agent_id, policy_id, policy_name, check_id, title,
                        result, compliance, remediation, scanned_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()),
                        agent_id,
                        item["policy_id"],
                        item.get("policy_name"),
                        item["check_id"],
                        item.get("title"),
                        item.get("result", "unknown"),
                        json.dumps(item.get("compliance")) if item.get("compliance") is not None else None,
                        item.get("remediation"),
                        scanned_at,
                    ),
                )
    return len(findings)


def get_agent_sca_last_scan_db(agent_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT max(scanned_at) FROM sca_findings WHERE agent_id = %s",
                (agent_id,),
            )
            row = cur.fetchone()
            if row and row[0]:
                return row[0].isoformat()
    return None


def get_agent_sca_summary_db(agent_id: str) -> dict[str, Any]:
    counts = {"passed": 0, "failed": 0, "notapplicable": 0, "other": 0}
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT result, count(*) AS cnt
                FROM sca_findings
                WHERE agent_id = %s AND check_id != 'none'
                GROUP BY result
                """,
                (agent_id,),
            )
            for row in cur.fetchall():
                result = str(row["result"] or "").lower()
                cnt = int(row["cnt"] or 0)
                if result in {"passed", "pass"}:
                    counts["passed"] += cnt
                elif result in {"failed", "fail"}:
                    counts["failed"] += cnt
                elif result in {"notapplicable", "not applicable", "n/a", "not_applicable"}:
                    counts["notapplicable"] += cnt
                else:
                    counts["other"] += cnt

            cur.execute(
                """
                SELECT policy_id, policy_name, check_id, title, result, remediation
                FROM sca_findings
                WHERE agent_id = %s AND result IN ('failed', 'fail')
                ORDER BY policy_id, check_id
                LIMIT 10
                """,
                (agent_id,),
            )
            top_failed = [_row_to_dict(dict(r)) for r in cur.fetchall()]

    scored = counts["passed"] + counts["failed"]
    score_percent = round((counts["passed"] / scored) * 100, 1) if scored else None
    return {
        "counts": counts,
        "score_percent": score_percent,
        "failed_count": counts["failed"],
        "top_failed": top_failed,
    }


def get_fleet_sca_summary_db() -> dict[str, Any]:
    fleet: list[dict[str, Any]] = []
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT h.agent_id, h.name, host(h.ip) AS ip,
                       max(s.scanned_at) AS scanned_at,
                       sum(CASE WHEN s.result IN ('passed', 'pass') THEN 1 ELSE 0 END) AS passed,
                       sum(CASE WHEN s.result IN ('failed', 'fail') THEN 1 ELSE 0 END) AS failed
                FROM hosts h
                LEFT JOIN sca_findings s ON s.agent_id = h.agent_id AND s.check_id != 'none'
                WHERE h.agent_id != '000'
                GROUP BY h.agent_id, h.name, h.ip
                ORDER BY h.name
                """
            )
            for row in cur.fetchall():
                passed = int(row["passed"] or 0)
                failed = int(row["failed"] or 0)
                scored = passed + failed
                fleet.append(
                    {
                        "agent_id": str(row["agent_id"]),
                        "name": row["name"],
                        "ip": str(row["ip"]) if row["ip"] else "",
                        "scanned_at": row["scanned_at"].isoformat() if row["scanned_at"] else None,
                        "passed": passed,
                        "failed": failed,
                        "score_percent": round((passed / scored) * 100, 1) if scored else None,
                    }
                )
    return {"source": "postgres+wazuh_sca", "fleet": fleet}


def replace_agent_user_findings_db(
    *,
    agent_id: str,
    findings: list[dict[str, Any]],
    scanned_at: datetime,
) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_findings WHERE agent_id = %s", (agent_id,))
            rows = findings if findings else [
                {
                    "username": "_none_",
                    "uid": None,
                    "gid": None,
                    "shell": None,
                    "last_login": None,
                    "risk_level": "info",
                }
            ]
            for item in rows:
                cur.execute(
                    """
                    INSERT INTO user_findings (
                        id, agent_id, username, uid, gid, shell, last_login,
                        risk_level, scanned_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()),
                        agent_id,
                        item["username"],
                        item.get("uid"),
                        item.get("gid"),
                        item.get("shell"),
                        item.get("last_login"),
                        item.get("risk_level", "info"),
                        scanned_at,
                    ),
                )
    return len(findings)


def get_agent_user_findings_db(
    agent_id: str,
    *,
    risk_level: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    sql = """
        SELECT agent_id, username, uid, gid, shell, last_login, risk_level, scanned_at
        FROM user_findings
        WHERE agent_id = %s AND username != '_none_'
    """
    params: list[Any] = [agent_id]
    if risk_level:
        sql += " AND risk_level = %s"
        params.append(risk_level.lower())
    sql += """
        ORDER BY CASE risk_level
        WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
        WHEN 'low' THEN 4 ELSE 5 END, username LIMIT %s"""
    params.append(limit)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]


def get_agent_user_risk_counts_db(agent_id: str) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT risk_level, count(*) FROM user_findings
                WHERE agent_id = %s AND username != '_none_'
                GROUP BY risk_level
                """,
                (agent_id,),
            )
            for level, cnt in cur.fetchall():
                key = str(level).lower()
                if key not in counts:
                    key = "info"
                counts[key] = int(cnt)
    return counts


def get_agent_user_last_scan_db(agent_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT max(scanned_at) FROM user_findings WHERE agent_id = %s",
                (agent_id,),
            )
            row = cur.fetchone()
            if row and row[0]:
                return row[0].isoformat()
    return None


def create_posture_scan_job_db(
    *,
    job_id: str,
    agent_ids: list[str],
    trigger: str,
    agent_id: str | None = None,
) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO posture_scan_jobs (
                    job_id, agent_id, agent_ids, status, trigger,
                    agents_total, agents_completed, results, started_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    job_id,
                    agent_id,
                    json.dumps(agent_ids),
                    "queued",
                    trigger,
                    len(agent_ids),
                    0,
                    json.dumps({}),
                    datetime.utcnow(),
                ),
            )


def update_posture_scan_job_db(
    job_id: str,
    *,
    status: str | None = None,
    agents_completed: int | None = None,
    results: dict[str, Any] | None = None,
    error: str | None = None,
    completed: bool = False,
) -> None:
    fields: list[str] = []
    params: list[Any] = []
    if status is not None:
        fields.append("status = %s")
        params.append(status)
    if agents_completed is not None:
        fields.append("agents_completed = %s")
        params.append(agents_completed)
    if results is not None:
        fields.append("results = %s")
        params.append(json.dumps(results))
    if error is not None:
        fields.append("error = %s")
        params.append(error)
    if completed:
        fields.append("completed_at = %s")
        params.append(datetime.utcnow())
    if not fields:
        return
    params.append(job_id)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE posture_scan_jobs SET {', '.join(fields)} WHERE job_id = %s",
                params,
            )


def get_posture_scan_job_db(job_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT job_id, agent_id, agent_ids, status, trigger,
                       agents_total, agents_completed, results, error,
                       started_at, completed_at
                FROM posture_scan_jobs WHERE job_id = %s
                """,
                (job_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return _row_to_dict(dict(row))
