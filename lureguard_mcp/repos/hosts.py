"""Host inventory."""

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
                       enrolled_by, enrolled_at, last_seen, criticality
                FROM hosts ORDER BY name
                """
            )
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]



def get_host_ip_db(agent_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT host(ip) FROM hosts WHERE agent_id = %s", (agent_id,))
            row = cur.fetchone()
            return str(row[0]) if row and row[0] else None



def set_host_criticality_db(agent_id: str, criticality: str) -> dict[str, Any]:
    allowed = {"critical", "high", "medium", "low"}
    crit = criticality.lower().strip()
    if crit not in allowed:
        raise ValueError(f"criticality must be one of {sorted(allowed)}")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE hosts SET criticality = %s WHERE agent_id = %s RETURNING agent_id, criticality",
                (crit, agent_id),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError(f"host {agent_id} not found")
    return {"agent_id": row[0], "criticality": row[1]}



def get_host_criticality_db(agent_id: str) -> str | None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT criticality FROM hosts WHERE agent_id = %s", (agent_id,))
            row = cur.fetchone()
            return row[0] if row else None


