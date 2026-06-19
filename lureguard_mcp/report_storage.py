"""Filesystem persistence for incident reports."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from lureguard_mcp.config import REPORTS_DIR


def write_report_markdown(*, title: str, markdown: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    slug = "".join(c if c.isalnum() else "-" for c in title.lower())[:40].strip("-")
    date_prefix = datetime.utcnow().strftime("%Y%m%d")
    filename = f"{date_prefix}-{slug or 'report'}.md"
    path = REPORTS_DIR / filename
    path.write_text(markdown, encoding="utf-8")
    return path
