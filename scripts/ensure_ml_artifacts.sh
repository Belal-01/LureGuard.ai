#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODEL_DIR="$ROOT/ml/models"
PYTHON="${ROOT}/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  bash "$ROOT/scripts/setup_venv.sh"
  PYTHON="${ROOT}/.venv/bin/python"
fi

if [[ -f "$MODEL_DIR/model.joblib" && -f "$MODEL_DIR/scaler.joblib" ]]; then
  echo "ML artifacts present in ml/models"
  exit 0
fi

echo "Training ML artifacts (quick run)..."
cd "$ROOT"
"$PYTHON" -m ml.train --n-samples 15000 --output-dir ml/models
