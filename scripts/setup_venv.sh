#!/usr/bin/env bash
# Create repo-root .venv (migrates legacy modules/ai/.venv if present).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LEGACY_VENV="$ROOT/modules/ai/.venv"
ROOT_VENV="$ROOT/.venv"

if [[ -d "$LEGACY_VENV" && ! -d "$ROOT_VENV" ]]; then
  echo "Moving modules/ai/.venv → .venv"
  mv "$LEGACY_VENV" "$ROOT_VENV"
fi

PYTHON_BIN="python3"
for candidate in python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PYTHON_BIN="$candidate"
    break
  fi
done

if [[ ! -d "$ROOT_VENV" ]]; then
  echo "Creating .venv at repo root with $PYTHON_BIN..."
  "$PYTHON_BIN" -m venv "$ROOT_VENV"
fi

"$ROOT_VENV/bin/pip" install --upgrade pip
"$ROOT_VENV/bin/pip" install -e ".[dev]"
# Optional dev tools (may be unavailable on very new Python versions)
"$ROOT_VENV/bin/pip" install ruff mypy 2>/dev/null || true

echo "Ready: source .venv/bin/activate"
