.PHONY: up down build test train ensure-ml lint format clean core venv db-up db-wait

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

up:
	docker compose up -d

venv:
	bash scripts/setup_venv.sh

ensure-ml: venv
	bash scripts/ensure_ml_artifacts.sh

db-up:
	docker compose up -d postgres

db-wait:
	@echo "Waiting for Postgres on localhost:5433..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		docker compose exec -T postgres pg_isready -U lureguard -d lureguard >/dev/null 2>&1 && exit 0; \
		sleep 1; \
	done; \
	echo "Postgres not ready — run: docker compose logs postgres"; exit 1

core: venv db-up db-wait
	@set -a; [ -f .env ] && . ./.env; set +a; \
	export DATABASE_URL="$${DATABASE_URL:-postgresql+asyncpg://lureguard:lureguard@localhost:5433/lureguard}"; \
	cd core && PYTHONPATH=.. CONFIG_PATH=../config/core.yaml MODELS_DIR=../ml/models \
	../$(PYTHON) -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload

up-llm:
	docker compose --profile local-llm up -d

down:
	docker compose down

build:
	docker compose build

test: venv
	$(PYTHON) -m pytest tests/ -v --cov=core --cov=ml --cov-report=term-missing

train: ensure-ml
	$(PYTHON) -m ml.train --n-samples 15000 --output-dir ml/models

lint: venv
	@if [ -x $(VENV)/bin/ruff ]; then $(VENV)/bin/ruff check core/ ml/ tests/; else echo "ruff not installed (optional)"; fi
	@if [ -x $(VENV)/bin/mypy ]; then $(VENV)/bin/mypy core/; else echo "mypy not installed (optional)"; fi

format: venv
	$(VENV)/bin/ruff format core/ ml/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
