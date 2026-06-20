"""IP blocklist persistence."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import psycopg2.extras

from lureguard_mcp.presentation import shape_event_row
from lureguard_mcp.repos.connection import get_conn


def add_blocklist_db(
    *,
    ip: str,
    reason: str,
    investigation_id: str | None = None,
    added_by: str = "agent",
) -> dict[str, Any]:
    block_id = str(uuid.uuid4())
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO blocklist (id, ip, reason, investigation_id, added_by, added_at, executed)
                VALUES (%s, %s::inet, %s, %s, %s, %s, false)
                ON CONFLICT (ip) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    investigation_id = COALESCE(EXCLUDED.investigation_id, blocklist.investigation_id),
                    added_by = EXCLUDED.added_by,
                    added_at = EXCLUDED.added_at,
                    executed = false,
                    executed_at = NULL
                RETURNING id, host(ip) AS ip, reason, executed, added_at
                """,
                (block_id, ip, reason, investigation_id, added_by, datetime.utcnow()),
            )
            row = cur.fetchone()
    return {
        "block_id": str(row[0]),
        "ip": str(row[1]),
        "reason": row[2],
        "executed": row[3],
        "added_at": row[4].isoformat() if row[4] else None,
        "status": "pending_human_confirmation",
    }



def confirm_blocklist_db(block_id: str, *, notes: str | None = None) -> dict[str, Any] | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                UPDATE blocklist
                SET executed = true, executed_at = %s, notes = COALESCE(%s, notes)
                WHERE id = %s
                RETURNING id, host(ip) AS ip, reason, investigation_id, executed_at
                """,
                (datetime.utcnow(), notes, block_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            return shape_event_row(dict(row))



def list_blocklist_db(*, pending_only: bool = False) -> list[dict]:
    clause = "WHERE executed = false" if pending_only else ""
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT id, host(ip) AS ip, reason, investigation_id, added_by,
                       added_at, executed, executed_at, notes
                FROM blocklist {clause}
                ORDER BY added_at DESC
                """
            )
            return [shape_event_row(dict(r)) for r in cur.fetchall()]



def get_blocklist_entry_db(block_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, host(ip) AS ip, reason, investigation_id, executed
                FROM blocklist WHERE id = %s
                """,
                (block_id,),
            )
            row = cur.fetchone()
            return shape_event_row(dict(row)) if row else None


