"""Report chart generation — matplotlib PNG only, embedded in markdown."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from lureguard_mcp.config import REPORTS_DIR
from lureguard_mcp.db import get_conn

VISUAL_SUMMARY_HEADER = "## Visual summary"

_CHART_TYPES = frozenset({"bar", "hbar", "line", "pie"})

_PRESET_TITLES = {
    "events_by_channel": "Events by channel (24h)",
    "alert_level_distribution": "Alert level distribution (24h)",
    "cve_by_severity": "CVEs by severity",
    "investigation_timeline": "Investigation timeline",
}


def report_stem_from_title(title: str) -> str:
    slug = "".join(c if c.isalnum() else "-" for c in title.lower())[:40].strip("-")
    date_prefix = datetime.utcnow().strftime("%Y%m%d")
    return f"{date_prefix}-{slug or 'report'}"


def _asset_dir(report_stem: str) -> Path:
    path = REPORTS_DIR / "assets" / report_stem
    path.mkdir(parents=True, exist_ok=True)
    return path


def _markdown_embed(title: str, png_path: Path) -> str:
    try:
        rel = png_path.resolve().relative_to(REPORTS_DIR.resolve())
    except ValueError:
        rel = png_path.name
    return f"![{title}]({rel.as_posix()})"


def _slug_filename(title: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")[:48]
    return base or "chart"


def generate_chart_png(
    title: str,
    chart_type: str,
    labels: list[str],
    values: list[float],
    *,
    report_stem: str,
    filename: str = "",
) -> dict[str, Any]:
    """Render a chart to PNG and return paths for markdown embedding."""
    kind = chart_type.lower().strip()
    if kind not in _CHART_TYPES:
        raise ValueError(f"chart_type must be one of {sorted(_CHART_TYPES)}")
    if not labels or not values or len(labels) != len(values):
        raise ValueError("labels and values must be non-empty lists of equal length")

    asset_dir = _asset_dir(report_stem)
    fname = filename or f"{_slug_filename(title)}.png"
    if not fname.endswith(".png"):
        fname = f"{fname}.png"
    png_path = asset_dir / fname

    fig, ax = plt.subplots(figsize=(8, 4.5))
    try:
        if kind == "bar":
            ax.bar(labels, values)
        elif kind == "hbar":
            ax.barh(labels, values)
        elif kind == "line":
            ax.plot(labels, values, marker="o")
        elif kind == "pie":
            ax.pie(values, labels=labels, autopct="%1.0f%%", startangle=90)
        ax.set_title(title)
        fig.tight_layout()
        fig.savefig(png_path, format="png", dpi=120)
    finally:
        plt.close(fig)

    return {
        "path": str(png_path),
        "markdown_embed": _markdown_embed(title, png_path),
        "filename": png_path.name,
    }


def _query_events_by_channel(*, hours: int = 24) -> tuple[list[str], list[float]]:
    since = datetime.utcnow() - timedelta(hours=hours)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT channel, count(*) AS cnt
                FROM events
                WHERE ts >= %s
                GROUP BY channel
                ORDER BY cnt DESC
                LIMIT 12
                """,
                (since,),
            )
            rows = cur.fetchall()
    if not rows:
        return [], []
    labels = [str(r[0]) for r in rows]
    values = [float(r[1]) for r in rows]
    return labels, values


def _query_alert_level_distribution(*, hours: int = 24) -> tuple[list[str], list[float]]:
    since = datetime.utcnow() - timedelta(hours=hours)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    CASE
                        WHEN wazuh_rule_level >= 12 THEN '12+ critical'
                        WHEN wazuh_rule_level >= 10 THEN '10-11 high'
                        WHEN wazuh_rule_level >= 7 THEN '7-9 medium'
                        WHEN wazuh_rule_level >= 3 THEN '3-6 low'
                        ELSE '0-2 info'
                    END AS band,
                    count(*) AS cnt
                FROM events
                WHERE ts >= %s AND wazuh_rule_level IS NOT NULL
                GROUP BY 1
                ORDER BY 1
                """,
                (since,),
            )
            rows = cur.fetchall()
    if not rows:
        return [], []
    return [str(r[0]) for r in rows], [float(r[1]) for r in rows]


def _query_cve_by_severity(*, agent_id: str = "") -> tuple[list[str], list[float]]:
    clauses = ["1=1"]
    params: list[Any] = []
    if agent_id.strip():
        clauses.append("agent_id = %s")
        params.append(agent_id.strip())
    sql = f"""
        SELECT coalesce(severity, 'unknown') AS sev, count(*) AS cnt
        FROM cve_findings
        WHERE {' AND '.join(clauses)}
        GROUP BY sev
        ORDER BY cnt DESC
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    if not rows:
        return [], []
    return [str(r[0]) for r in rows], [float(r[1]) for r in rows]


def _query_investigation_timeline(*, investigation_id: str) -> tuple[list[str], list[float]]:
    if not investigation_id.strip():
        return [], []
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT ts_event, description
                FROM timeline_events
                WHERE investigation_id = %s
                ORDER BY ts_event ASC
                LIMIT 20
                """,
                (investigation_id.strip(),),
            )
            rows = cur.fetchall()
    if not rows:
        return [], []
    labels: list[str] = []
    values: list[float] = []
    for idx, row in enumerate(rows):
        ts = row[0]
        desc = str(row[1] or "")[:24]
        if hasattr(ts, "strftime"):
            labels.append(ts.strftime("%H:%M") + f" {desc[:12]}")
        else:
            labels.append(f"E{idx + 1}")
        values.append(float(idx + 1))
    return labels, values


def generate_chart_from_preset(
    preset: str,
    *,
    report_stem: str,
    hours: int = 24,
    agent_id: str = "",
    investigation_id: str = "",
) -> dict[str, Any] | None:
    """Run a named DB preset and return chart result, or None if no data."""
    key = preset.strip().lower()
    chart_type = "pie"
    if key == "events_by_channel":
        labels, values = _query_events_by_channel(hours=hours)
        chart_type = "bar"
    elif key == "alert_level_distribution":
        labels, values = _query_alert_level_distribution(hours=hours)
        chart_type = "pie"
    elif key == "cve_by_severity":
        labels, values = _query_cve_by_severity(agent_id=agent_id)
        chart_type = "bar"
    elif key == "investigation_timeline":
        labels, values = _query_investigation_timeline(investigation_id=investigation_id)
        chart_type = "bar"
    else:
        raise ValueError(
            f"unknown preset {preset!r}; use events_by_channel, alert_level_distribution, "
            "cve_by_severity, investigation_timeline"
        )

    if not labels:
        return None

    title = _PRESET_TITLES.get(key, key.replace("_", " ").title())
    return generate_chart_png(
        title,
        chart_type,
        labels,
        values,
        report_stem=report_stem,
        filename=f"{key}.png",
    )


def _presets_for_title(title: str) -> list[str]:
    lower = title.lower()
    if "posture" in lower or "cve" in lower:
        return ["cve_by_severity"]
    if "daily" in lower or "summary" in lower:
        return ["events_by_channel", "alert_level_distribution"]
    if "incident" in lower or "investigation" in lower or "attack" in lower:
        return ["investigation_timeline", "alert_level_distribution"]
    return ["events_by_channel", "alert_level_distribution"]


def enrich_report_markdown(
    markdown: str,
    *,
    title: str,
    investigation_id: str = "",
    report_stem: str = "",
) -> dict[str, Any]:
    """Append ## Visual summary with PNG embeds from default presets."""
    stem = report_stem or report_stem_from_title(title)
    existing = VISUAL_SUMMARY_HEADER in markdown
    embeds: list[str] = []
    charts_added: list[str] = []

    presets = list(_presets_for_title(title))
    if investigation_id and "investigation_timeline" not in presets:
        presets.insert(0, "investigation_timeline")

    for preset in presets:
        if preset in markdown:
            continue
        try:
            result = generate_chart_from_preset(
                preset,
                report_stem=stem,
                investigation_id=investigation_id,
            )
        except Exception:
            continue
        if not result:
            continue
        embeds.append(result["markdown_embed"])
        charts_added.append(preset)

    if not embeds:
        return {"markdown": markdown, "report_stem": stem, "charts_added": charts_added}

    block = VISUAL_SUMMARY_HEADER + "\n\n" + "\n\n".join(embeds) + "\n"
    if existing:
        enriched = markdown.rstrip() + "\n\n" + "\n\n".join(embeds) + "\n"
    else:
        enriched = markdown.rstrip() + "\n\n" + block

    return {
        "markdown": enriched,
        "report_stem": stem,
        "charts_added": charts_added,
        "embeds": embeds,
    }


def charts_available() -> bool:
    try:
        import matplotlib  # noqa: F401

        return True
    except ImportError:
        return False
