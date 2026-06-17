"""Tests for markdown → PDF pipeline (WeasyPrint primary, xhtml2pdf fallback)."""

from __future__ import annotations

from pathlib import Path

import pytest

from lureguard_mcp.report_pdf import (
    convert_markdown_text_to_pdf_bytes,
    markdown_to_html,
    pdf_available,
    resolve_report_pdf_path,
    weasyprint_available,
)


@pytest.mark.skipif(not pdf_available(), reason="PDF deps not installed")
def test_markdown_to_html_embeds_local_png_as_data_uri(tmp_path: Path):
    png = tmp_path / "chart.png"
    png.write_bytes(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
        b"\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    md = f"# Title\n\n![chart]({png.name})\n"
    html = markdown_to_html(md, base_dir=tmp_path)
    assert 'src="data:image/png;base64,' in html
    assert 'class="report-chart"' in html


@pytest.mark.skipif(not pdf_available(), reason="PDF deps not installed")
def test_convert_markdown_text_to_pdf_bytes(tmp_path: Path):
    md = "# Hello\n\nParagraph with **bold**.\n\n| A | B |\n|---|---|\n| 1 | 2 |\n"
    pdf_bytes = convert_markdown_text_to_pdf_bytes(md, base_dir=tmp_path)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 100


@pytest.mark.skipif(not pdf_available(), reason="PDF deps not installed")
def test_resolve_report_pdf_path_accepts_pdf_input(tmp_path: Path):
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"%PDF-1.4 test")
    resolved, mode = resolve_report_pdf_path(pdf)
    assert resolved == pdf.resolve()
    assert mode == "pdf_input"


@pytest.mark.skipif(not pdf_available(), reason="PDF deps not installed")
def test_resolve_report_pdf_path_reuses_existing_sibling(tmp_path: Path):
    md = tmp_path / "report.md"
    pdf = tmp_path / "report.pdf"
    md.write_text("# Hi\n", encoding="utf-8")
    pdf.write_bytes(b"%PDF-1.4 test")
    # PDF newer than md
    import os
    import time

    now = time.time()
    os.utime(md, (now - 10, now - 10))
    os.utime(pdf, (now, now))

    resolved, mode = resolve_report_pdf_path(md)
    assert resolved == pdf.resolve()
    assert mode == "reused"


@pytest.mark.skipif(not pdf_available(), reason="PDF deps not installed")
def test_pdf_embeds_chart_image(tmp_path: Path):
    png = tmp_path / "chart.png"
    png.write_bytes(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
        b"\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    md = f"# Chart test\n\n![chart]({png.name})\n"
    pdf_bytes = convert_markdown_text_to_pdf_bytes(md, base_dir=tmp_path)
    image_refs = pdf_bytes.count(b"/Subtype /Image")
    if weasyprint_available():
        assert image_refs >= 1
    else:
        assert image_refs >= 1 or b"chart" in pdf_bytes
