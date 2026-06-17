"""Markdown report → PDF via markdown + WeasyPrint (xhtml2pdf fallback). Charts stay PNG on disk."""

from __future__ import annotations

import base64
import mimetypes
import re
import tempfile
from pathlib import Path
from urllib.parse import unquote

from lureguard_mcp.config import REPORTS_DIR, REPO_ROOT

_IMG_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")

_REPORT_CSS = """
@page {
  size: A4;
  margin: 18mm 14mm;
}
body {
  font-family: Helvetica, Arial, sans-serif;
  font-size: 10pt;
  line-height: 1.45;
  color: #1a1a1a;
}
h1 { font-size: 17pt; margin: 0 0 0.6em; }
h2 { font-size: 13pt; margin: 1.1em 0 0.45em; page-break-after: avoid; }
h3 { font-size: 11pt; margin: 0.9em 0 0.35em; page-break-after: avoid; }
p { margin: 0.4em 0 0.7em; }
ul, ol { margin: 0.4em 0 0.8em; padding-left: 1.4em; }
table {
  border-collapse: collapse;
  width: 100%;
  font-size: 8pt;
  margin: 8px 0 12px;
  table-layout: auto;
  -pdf-keep-in-frame-mode: shrink;
}
thead { display: table-header-group; }
tr { page-break-inside: avoid; }
th, td {
  border: 1px solid #bbb;
  padding: 3px 5px;
  text-align: left;
  vertical-align: top;
  word-wrap: break-word;
  overflow-wrap: break-word;
}
th { background: #f0f0f0; font-weight: bold; }
img.report-chart {
  display: block;
  max-width: 100%;
  height: auto;
  margin: 10px 0 14px;
  page-break-inside: avoid;
}
code {
  font-family: Menlo, Consolas, monospace;
  font-size: 8pt;
  background: #f4f4f4;
  padding: 1px 3px;
}
"""


def weasyprint_available() -> bool:
    try:
        from weasyprint import HTML  # noqa: F401

        return True
    except (ImportError, OSError):
        return False


def xhtml2pdf_available() -> bool:
    try:
        from xhtml2pdf import pisa  # noqa: F401

        return True
    except ImportError:
        return False


def pdf_available() -> bool:
    return weasyprint_available() or xhtml2pdf_available()


def pandoc_available() -> bool:
    """Backward-compatible alias — PDF uses bundled pip deps, not pandoc."""
    return pdf_available()


def _resolve_image_path(raw: str, base_dir: Path) -> Path | None:
    text = unquote(raw.strip().strip('"').strip("'"))
    if text.startswith(("http://", "https://", "data:")):
        return None
    path = Path(text)
    if not path.is_absolute():
        path = (base_dir / path).resolve()
    else:
        path = path.resolve()
    if path.is_file():
        return path
    alt = (REPORTS_DIR / text).resolve()
    if alt.is_file():
        return alt
    repo_alt = (REPO_ROOT / text).resolve()
    if repo_alt.is_file():
        return repo_alt
    return None


def _image_data_uri(path: Path) -> str:
    mime, _ = mimetypes.guess_type(path.name)
    if not mime:
        mime = "image/png"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def _embed_images_as_html(md_text: str, base_dir: Path) -> str:
    """Replace markdown image syntax with inline base64 HTML img tags."""

    def repl(match: re.Match[str]) -> str:
        alt = match.group(1)
        src = match.group(2)
        resolved = _resolve_image_path(src, base_dir)
        if not resolved:
            return match.group(0)
        uri = _image_data_uri(resolved)
        return f'<img src="{uri}" alt="{alt}" class="report-chart" />'

    return _IMG_RE.sub(repl, md_text)


def markdown_to_html(md_text: str, *, base_dir: Path | None = None) -> str:
    import markdown as md_lib

    root = base_dir or REPORTS_DIR
    with_images = _embed_images_as_html(md_text, root)
    body = md_lib.markdown(
        with_images,
        extensions=["tables", "fenced_code"],
        output_format="html5",
    )
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<style>
{_REPORT_CSS}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def _write_pdf_weasyprint(html: str, pdf_path: Path, base_url: Path) -> None:
    from weasyprint import HTML

    HTML(string=html, base_url=str(base_url)).write_pdf(pdf_path)


def _write_pdf_xhtml2pdf(html: str, pdf_path: Path, *, source_path: Path) -> None:
    from xhtml2pdf import pisa

    with open(pdf_path, "wb") as pdf_file:
        status = pisa.CreatePDF(
            html,
            dest=pdf_file,
            encoding="utf-8",
            path=str(source_path),
        )
    if status.err:
        raise RuntimeError(f"PDF conversion failed (xhtml2pdf errors: {status.err})")


def _write_pdf(html: str, pdf_path: Path, *, source_path: Path) -> str:
    if weasyprint_available():
        _write_pdf_weasyprint(html, pdf_path, source_path.parent)
        return "weasyprint"
    if xhtml2pdf_available():
        _write_pdf_xhtml2pdf(html, pdf_path, source_path=source_path)
        return "xhtml2pdf"
    raise RuntimeError(
        "PDF dependencies missing — run: make venv  (installs weasyprint + markdown)"
    )


def convert_markdown_to_pdf(md_path: Path) -> Path:
    """Convert a markdown report to PDF; embeds on-disk PNG references."""
    if not pdf_available():
        raise RuntimeError(
            "PDF dependencies missing — run: make venv  (installs weasyprint + markdown)"
        )

    md_path = md_path.resolve()
    if not md_path.is_file():
        raise FileNotFoundError(f"report not found: {md_path}")

    pdf_path = md_path.with_suffix(".pdf")
    html = markdown_to_html(md_path.read_text(encoding="utf-8"), base_dir=md_path.parent)
    _write_pdf(html, pdf_path, source_path=md_path)

    if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
        raise RuntimeError("PDF conversion produced an empty file")

    return pdf_path


def resolve_report_pdf_path(report_path: Path) -> tuple[Path, str]:
    """Resolve a PDF for upload: accept .pdf input, reuse fresh sibling, or convert .md."""
    report_path = report_path.resolve()
    if report_path.suffix.lower() == ".pdf":
        if not report_path.is_file():
            raise FileNotFoundError(f"report not found: {report_path}")
        return report_path, "pdf_input"

    if report_path.suffix.lower() != ".md":
        raise ValueError(f"expected .md or .pdf report, got: {report_path.name}")

    sibling = report_path.with_suffix(".pdf")
    if sibling.is_file() and sibling.stat().st_mtime >= report_path.stat().st_mtime:
        return sibling, "reused"

    return convert_markdown_to_pdf(report_path), "converted"


def convert_markdown_text_to_pdf_bytes(md_text: str, *, base_dir: Path | None = None) -> bytes:
    """Convert markdown string to PDF bytes (for tests)."""
    root = base_dir or REPORTS_DIR
    html = markdown_to_html(md_text, base_dir=root)
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
        out_path = Path(tmp_pdf.name)
    try:
        _write_pdf(html, out_path, source_path=root / "report.md")
        return out_path.read_bytes()
    finally:
        out_path.unlink(missing_ok=True)
