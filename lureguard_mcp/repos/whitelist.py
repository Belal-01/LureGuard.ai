"""whitelist entries mirror blocklist — pending recommend + human confirm."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import psycopg2.extras

from lureguard_mcp.presentation import row_to_dict, shape_event_row
from lureguard_mcp.repos.connection import get_conn


def _row_to_dict(row: dict[str, Any]) -> dict[str, Any]:
    return shape_event_row(row_to_dict(row))


def add_whitelist_db(
    *,
    ip: str,
    reason: str,
    investigation_id: str | None = None,
    added_by: str = "agent",
    executed: bool = False,
) -> dict[str, Any]:
    entry_id = str(uuid.uuid4())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO whitelist (
                    id, ip, reason, investigation_id, added_by, added_at, executed
                )
                VALUES (%s, %s::inet, %s, %s, %s, %s, %s)
                ON CONFLICT (ip) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    investigation_id = COALESCE(EXCLUDED.investigation_id, whitelist.investigation_id),
                    added_by = EXCLUDED.added_by,
                    added_at = EXCLUDED.added_at,
                    executed = EXCLUDED.executed,
                    executed_at = CASE WHEN EXCLUDED.executed THEN EXCLUDED.added_at ELSE NULL END,
                    notes = NULL
                RETURNING id, host(ip) AS ip, reason, executed, added_at
                """,
                (
                    entry_id,
                    ip,
                    reason,
                    investigation_id,
                    added_by,
                    datetime.utcnow(),
                    executed,
                ),
            )
            row = cur.fetchone()
    status = "active" if row[3] else "pending_human_confirmation"
    return {
        "whitelist_id": str(row[0]),
        "ip": str(row[1]),
        "reason": row[2],
        "executed": row[3],
        "added_at": row[4].isoformat() if row[4] else None,
        "status": status,
    }


def confirm_whitelist_db(whitelist_id: str, *, notes: str | None = None) -> dict[str, Any] | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE whitelist
                SET executed = true, executed_at = %s, notes = COALESCE(%s, notes)
                WHERE id = %s
                RETURNING id, host(ip) AS ip, reason, investigation_id, executed_at, notes
                """,
                (datetime.utcnow(), notes, whitelist_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            return _row_to_dict(dict(row))


def list_whitelist_db(*, pending_only: bool = False) -> list[dict]:
    clause = "WHERE executed = false" if pending_only else ""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT id, host(ip) AS ip, reason, investigation_id, added_by,
                       added_at, executed, executed_at, notes
                FROM whitelist {clause}
                ORDER BY added_at DESC
                """
            )
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]


def get_whitelist_entry_db(whitelist_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, host(ip) AS ip, reason, investigation_id, executed
                FROM whitelist WHERE id = %s
                """,
                (whitelist_id,),
            )
            row = cur.fetchone()
            return _row_to_dict(dict(row)) if row else None


def remove_whitelist_db(*, whitelist_id: str = "", ip: str = "") -> bool:
    if whitelist_id:
        sql = "DELETE FROM whitelist WHERE id = %s"
        param = whitelist_id
    elif ip:
        sql = "DELETE FROM whitelist WHERE ip = %s::inet"
        param = ip
    else:
        return False
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (param,))
            return cur.rowcount > 0
