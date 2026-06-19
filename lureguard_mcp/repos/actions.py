"""Agent action audit log."""

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
                    json.dumps(redact_mapping(args or {})),
                    (result_summary or "")[:4000],
                    duration_ms,
                    datetime.utcnow(),
                ),
            )


