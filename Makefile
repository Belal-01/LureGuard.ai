.PHONY: up down build test test-integration venv ensure-venv migrate doctor db-revision \
	fetch-dataset train train-quick lint format clean update-check update rollback-update demo loadtest eval check register

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build

ensure-venv:
	@command -v python3 >/dev/null || (echo "python3 required" && exit 1)
	@if [ ! -d $(VENV) ]; then python3 -m venv $(VENV); fi
	@if [ ! -x $(PYTHON) ]; then echo "Broken venv — remove .venv and run: make venv"; exit 1; fi

venv: ensure-venv
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev,train,mcp]"
	@$(PIP) install ruff mypy 2>/dev/null || true

migrate: ensure-venv
	@set -a; [ -f .env ] && . ./.env; set +a; \
	$(PYTHON) -m alembic -c migrations/alembic.ini upgrade head

doctor: ensure-venv
	@if ! $(PYTHON) -c "import lureguard_mcp" 2>/dev/null; then \
		echo "MCP deps missing — run: make venv"; exit 1; \
	fi
	@set -a; [ -f .env ] && . ./.env; set +a; \
	$(PYTHON) -m lureguard_mcp.doctor

update-check:
	python3 update-system.py check

update:
	python3 update-system.py apply

rollback-update:
	python3 update-system.py rollback

db-revision: venv
	@if [ -z "$(m)" ]; then echo "Usage: make db-revision m=\"message\""; exit 1; fi
	$(PYTHON) -m alembic -c migrations/alembic.ini revision --autogenerate -m "$(m)"

test: venv
	$(PYTHON) -m pytest tests/ -v -m "not integration and not acceptance" --cov=core --cov=ml --cov=lureguard_mcp --cov-report=term-missing

# Change-register definition-of-done. Failures here are open register items,
# not broken code. See tests/acceptance/test_register.py.
check: venv
	@$(PYTHON) -m pytest tests/acceptance/ -m acceptance --no-header -q --tb=line || true

test-integration: venv
	$(PYTHON) -m pytest tests/ -v -m integration

# INS-2: load the deterministic demo dataset (500 normalized events) into
# Postgres so there's something to triage in ~2 minutes, no Wazuh/agents/
# attacker required. Idempotent — ids are deterministic, re-running inserts
# nothing new (see demo_seed.load_demo).
demo: ensure-venv
	@set -a; [ -f .env ] && . ./.env; set +a; \
	PYTHONPATH=core:. $(PYTHON) -c "import asyncio; from demo_seed import load_demo; n = asyncio.run(load_demo()); print(f'demo: inserted {n} new event(s)')"

# VER-1: score the product's own decision path (decision_policy.decide over
# inference.infer_event) against the demo dataset's generator-known labels —
# offline, no database. Prints TPR/FPR and the confusion matrix.
# PYTHONHASHSEED pinned: ml/alert_features.decoder_hash_value feeds the model
# a feature derived from the builtin hash() of a string, which Python
# randomizes per-process by default — without pinning it, TPR/FPR would
# change on every run for reasons that have nothing to do with the model.
eval: ensure-venv
	PYTHONHASHSEED=0 PYTHONPATH=core:. $(PYTHON) -m evaluate

# ARC-1/ING-3: drive POST /wazuh/event at RATE req/s for DURATION seconds and
# report latency percentiles, an outcome breakdown (ok/timeout/connection_error/
# http_error), and achieved-vs-requested rate (core/loadtest.py). Discards a
# short warm-up, then samples MEM_CONTAINER's memory continuously through the
# run (not point-in-time snapshots) so footprint-under-load is more than an
# idle guess. Override: make loadtest RATE=50 DURATION=60
RATE ?= 20
DURATION ?= 30
URL ?= http://localhost:8080/wazuh/event
MEM_CONTAINER ?= wazuh-manager
loadtest: ensure-venv
	@set -a; [ -f .env ] && . ./.env; set +a; \
	PYTHONPATH=core:. $(PYTHON) -m loadtest --rate $(RATE) --duration $(DURATION) --url $(URL) --mem-container $(MEM_CONTAINER)

fetch-dataset: venv
	$(PYTHON) -c "from ml.dataset_loaders import ensure_true_labeled_dataset; ensure_true_labeled_dataset()"

train: venv
	$(PYTHON) -m ml.train --output-dir ml/models

train-quick: venv
	$(PYTHON) -m ml.train --sample-cap 100000 --output-dir ml/models

lint: venv
	@if [ -x $(VENV)/bin/ruff ]; then $(VENV)/bin/ruff check core/ ml/ tests/ lureguard_mcp/; else echo "ruff not installed (optional)"; fi
	@if [ -x $(VENV)/bin/mypy ]; then $(VENV)/bin/mypy core/; else echo "mypy not installed (optional)"; fi

format: venv
	$(VENV)/bin/ruff format core/ ml/ tests/ lureguard_mcp/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete

# Regenerate the register board + counts from the item tables, then render the
# shareable HTML. Run after editing any row in docs/CHANGE-REGISTER.md.
register:
	@python3 scripts/regen_board.py
	@python3 scripts/render_register.py register.html
