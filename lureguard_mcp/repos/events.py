"""Event and alert queries."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import psycopg2
import psycopg2.extras

from lureguard_mcp.presentation import infer_attack_phases, shape_event_row
from lureguard_mcp.repos.connection import get_conn


def _agent_event_filter(agent_id: str, agent_ip: str | None) -> tuple[str, list[Any]]:
    """Match events by agent_id with IP fallbacks for legacy rows."""
    params: list[Any] = [agent_id]
    clause = "(agent_id = %s"
    if agent_ip:
        clause += " OR (agent_id IS NULL AND (agent_ip = %s::inet OR src_ip = %s::inet))"
        params.extend([agent_ip, agent_ip])
    clause += ")"
    return clause, params



def _event_enriched_select(where_clause: str) -> str:
  return f"""
        SELECT e.id, e.ts, host(e.src_ip) AS src_ip, e.channel, e.event_type, e.username,
               e.wazuh_rule_id, e.wazuh_rule_level, e.wazuh_rule_description,
               e.geo_country, e.geo_city, e.agent_id, e.agent_name,
               e.syscheck_path, e.syscheck_event, e.raw_ref, e.profile_id,
               d.p AS ml_score, d.decision
        FROM events e
        LEFT JOIN decisions d ON d.event_id = e.id
        WHERE {where_clause}
    """



def get_recent_alerts(
    *,
    limit: int = 50,
    min_level: int | None = None,
    channel: str | None = None,
) -> list[dict]:
    clauses = ["1=1"]
    params: list[Any] = []
    if min_level is not None:
        clauses.append("e.wazuh_rule_level >= %s")
        params.append(min_level)
    if channel:
        clauses.append("e.channel = %s")
        params.append(channel)
    params.append(limit)
    sql = _event_enriched_select(" AND ".join(clauses)) + " ORDER BY e.ts DESC LIMIT %s"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [shape_event_row(dict(r)) for r in cur.fetchall()]



def get_alerts_for_ip(ip: str, *, limit: int = 100) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                _event_enriched_select("e.src_ip = %s::inet") + " ORDER BY e.ts DESC LIMIT %s",
                (ip, limit),
            )
            return [shape_event_row(dict(r)) for r in cur.fetchall()]



def get_event_timeline(ip: str, *, window_hours: int = 24) -> dict[str, Any]:
    since = datetime.utcnow() - timedelta(hours=window_hours)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                _event_enriched_select("e.src_ip = %s::inet AND e.ts >= %s")
                + " ORDER BY e.ts ASC",
                (ip, since),
            )
            events = [shape_event_row(dict(r)) for r in cur.fetchall()]
            cur.execute(
                """
                SELECT min(ts) AS first_seen, max(ts) AS last_seen,
                       EXTRACT(EPOCH FROM max(ts) - min(ts)) AS duration_seconds,
                       max(wazuh_rule_level) AS peak_level,
                       array_agg(DISTINCT channel) AS channels_seen,
                       max(geo_country) AS geo_country,
                       max(geo_city) AS geo_city
                FROM events
                WHERE src_ip = %s::inet AND ts >= %s
                """,
                (ip, since),
            )
            agg = dict(cur.fetchone() or {})
    first_seen = agg.get("first_seen")
    last_seen = agg.get("last_seen")
    duration_seconds = int(agg.get("duration_seconds") or 0)
    geo_country = agg.get("geo_country") or (events[0].get("geo_country") if events else None)
    geo_city = agg.get("geo_city") or (events[0].get("geo_city") if events else None)
    channels = agg.get("channels_seen") or []
    if isinstance(channels, list):
        channels_seen = [str(c) for c in channels if c]
    else:
        channels_seen = []
    geo_parts = [p for p in (geo_country, geo_city) if p]
    return {
        "ip": ip,
        "window_hours": window_hours,
        "geo": " / ".join(geo_parts) if geo_parts else None,
        "geo_country": geo_country,
        "geo_city": geo_city,
        "first_seen": first_seen.isoformat() if hasattr(first_seen, "isoformat") else first_seen,
        "last_seen": last_seen.isoformat() if hasattr(last_seen, "isoformat") else last_seen,
        "duration_seconds": duration_seconds,
        "duration_minutes": round(duration_seconds / 60, 1) if duration_seconds else 0,
        "channels_seen": channels_seen,
        "peak_level": int(agg.get("peak_level") or 0),
        "attack_phases": infer_attack_phases(events),
        "events": events,
    }



def get_attack_summary(ip: str, *, window_hours: int = 48) -> dict[str, Any]:
    timeline = get_event_timeline(ip, window_hours=window_hours)
    events = timeline.get("events") or []
    rule_counts: dict[str, int] = {}
    for ev in events:
        desc = ev.get("wazuh_rule_description") or f"rule_{ev.get('wazuh_rule_id')}"
        rule_counts[desc] = rule_counts.get(desc, 0) + 1
    top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:5]
    return {
        "ip": ip,
        "geo": timeline.get("geo"),
        "first_seen": timeline.get("first_seen"),
        "last_seen": timeline.get("last_seen"),
        "duration_minutes": timeline.get("duration_minutes"),
        "event_count": len(events),
        "channels_seen": timeline.get("channels_seen"),
        "peak_level": timeline.get("peak_level"),
        "attack_phases": timeline.get("attack_phases"),
        "top_rules": [{"rule": r, "count": c} for r, c in top_rules],
        "honeypot_contact": "honeypot_contact" in (timeline.get("attack_phases") or []),
        "max_ml_score": max((e.get("ml_score") or 0 for e in events), default=None),
    }



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
        clauses.append("e.src_ip = %s::inet")
        params.append(ip)
    if channel:
        clauses.append("e.channel = %s")
        params.append(channel)
    if min_level is not None:
        clauses.append("e.wazuh_rule_level >= %s")
        params.append(min_level)
    if username:
        clauses.append("e.username ILIKE %s")
        params.append(f"%{username}%")
    params.append(limit)
    sql = _event_enriched_select(" AND ".join(clauses)) + " ORDER BY e.ts DESC LIMIT %s"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [shape_event_row(dict(r)) for r in cur.fetchall()]



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



def mark_event_watched_db(event_id: str, investigation_id: str | None = None) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO watched_events (event_id, watched_at, investigation_id)
                VALUES (%s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                """,
                (event_id, datetime.utcnow(), investigation_id),
            )



def is_event_watched_db(event_id: str) -> bool:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM watched_events WHERE event_id = %s", (event_id,))
            return cur.fetchone() is not None



def get_high_level_events_since_db(since: datetime, min_level: int) -> list[dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT e.id, e.ts, host(e.src_ip) AS src_ip, e.channel, e.event_type,
                       e.wazuh_rule_id, e.wazuh_rule_level, e.wazuh_rule_description,
                       e.agent_id, e.agent_name
                FROM events e
                LEFT JOIN watched_events w ON w.event_id = e.id
                WHERE e.ts >= %s AND e.wazuh_rule_level >= %s AND w.event_id IS NULL
                ORDER BY e.ts ASC
                LIMIT 50
                """,
                (since, min_level),
            )
            return [shape_event_row(dict(r)) for r in cur.fetchall()]
