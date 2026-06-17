"""Tests for report chart PNG generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from lureguard_mcp.report_charts import (
    VISUAL_SUMMARY_HEADER,
    enrich_report_markdown,
    generate_chart_png,
)


def test_generate_chart_png_writes_file(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from lureguard_mcp import report_charts

    monkeypatch.setattr(report_charts, "REPORTS_DIR", tmp_path)

    result = generate_chart_png(
        "Test chart",
        "bar",
        ["a", "b"],
        [1.0, 2.0],
        report_stem="test-report",
    )
    png = Path(result["path"])
    assert png.is_file()
    assert png.suffix == ".png"
    assert "![Test chart]" in result["markdown_embed"]
    assert result["markdown_embed"].endswith(".png)")


def test_enrich_report_markdown_appends_visual_summary(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from lureguard_mcp import report_charts

    monkeypatch.setattr(report_charts, "REPORTS_DIR", tmp_path)

    def fake_preset(preset: str, **kwargs):
        if preset == "events_by_channel":
            return generate_chart_png(
                "Events",
                "bar",
                ["sshd"],
                [5.0],
                report_stem=kwargs.get("report_stem", "x"),
                filename="events_by_channel.png",
            )
        return None

    monkeypatch.setattr(report_charts, "generate_chart_from_preset", fake_preset)

    out = enrich_report_markdown("# Report\n\nBody.", title="Daily SOC Summary")
    assert VISUAL_SUMMARY_HEADER in out["markdown"]
    assert "![Events]" in out["markdown"]
    assert "events_by_channel" in out["charts_added"]
