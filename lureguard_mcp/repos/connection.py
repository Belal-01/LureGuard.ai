"""Postgres connection helper for MCP repos."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

import psycopg2

from lureguard_mcp.config import database_url_sync


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
