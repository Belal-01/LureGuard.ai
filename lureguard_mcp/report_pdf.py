"""Optional markdown → PDF conversion for reports (opt-in only)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_PDF_ENGINES = ("pdflatex", "xelatex", "lualatex", "tectonic")


def pandoc_available() -> bool:
    return shutil.which("pandoc") is not None


def convert_markdown_to_pdf(md_path: Path) -> Path:
    """Convert a markdown report to PDF via pandoc. Raises RuntimeError on failure."""
    if not pandoc_available():
        raise RuntimeError(
            "pandoc not installed — install with: brew install pandoc basictex (macOS) "
            "or apt install pandoc texlive-xetex (Ubuntu)"
        )

    pdf_path = md_path.with_suffix(".pdf")
    errors: list[str] = []

    for engine in _PDF_ENGINES:
        cmd = [
            "pandoc",
            str(md_path),
            "-o",
            str(pdf_path),
            "--pdf-engine",
            engine,
            "-V",
            "geometry:margin=1in",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0 and pdf_path.is_file():
            return pdf_path
        err = (result.stderr or result.stdout or "").strip()
        if err:
            errors.append(f"{engine}: {err[:200]}")

    cmd = ["pandoc", str(md_path), "-o", str(pdf_path), "-V", "geometry:margin=1in"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode == 0 and pdf_path.is_file():
        return pdf_path

    detail = errors[-1] if errors else (result.stderr or result.stdout or "unknown error")
    raise RuntimeError(f"PDF conversion failed: {detail[:400]}")
