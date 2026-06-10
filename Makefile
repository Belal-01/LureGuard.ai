.PHONY: up down build test train train-quick ensure-ml fetch-dataset lint format clean core venv db-up db-wait

VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

up:
	docker compose up -d

venv:
	@command -v python3 >/dev/null || (echo "python3 required" && exit 1)
	@if [ ! -d $(VENV) ]; then python3 -m venv $(VENV); fi
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev,train]"
	@$(PIP) install ruff mypy 2>/dev/null || true

ensure-ml:
	@test -f ml/models/model.joblib && test -f ml/models/scaler.joblib || \
		(echo "Missing ml/models/model.joblib — git pull or: make train" && exit 1)
	@echo "ML artifacts OK (model.joblib + scaler.joblib)"

db-up:
	docker compose up -d postgres

db-wait:
	@echo "Waiting for Postgres on localhost:5433..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		docker compose exec -T postgres pg_isready -U lureguard -d lureguard >/dev/null 2>&1 && exit 0; \
		sleep 1; \
	done; \
	echo "Postgres not ready — run: docker compose logs postgres"; exit 1

db-revision: venv
	@if [ -z "$(m)" ]; then echo "Usage: make db-revision m=\"message\""; exit 1; fi
	$(PYTHON) -m alembic -c migrations/alembic.ini revision --autogenerate -m "$(m)"

core: venv db-up db-wait
	@set -a; [ -f .env ] && . ./.env; set +a; \
	cd core && PYTHONPATH=.. CONFIG_PATH=../config/core.yaml MODELS_DIR=../ml/models \
	../$(PYTHON) -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload

up-llm:
	docker compose --profile local-llm up -d

down:
	docker compose down

build:
	docker compose build

test: venv
	$(PYTHON) -m pytest tests/ -v -m "not integration" --cov=core --cov=ml --cov-report=term-missing

test-integration: venv
	$(PYTHON) -m pytest tests/ -v -m integration

fetch-dataset: venv
	$(PYTHON) -c "from ml.dataset_loaders import ensure_true_labeled_dataset; ensure_true_labeled_dataset()"

train: venv
	$(PYTHON) -m ml.train --output-dir ml/models
	$(PYTHON) -m ml.generate_tutor_report

tutor-report: venv
	$(PYTHON) -m ml.generate_tutor_report

train-full: venv
	$(PYTHON) -m ml.train --full --output-dir ml/models

train-quick: venv
	$(PYTHON) -m ml.train --sample-cap 100000 --output-dir ml/models

lint: venv
	@if [ -x $(VENV)/bin/ruff ]; then $(VENV)/bin/ruff check core/ ml/ tests/; else echo "ruff not installed (optional)"; fi
	@if [ -x $(VENV)/bin/mypy ]; then $(VENV)/bin/mypy core/; else echo "mypy not installed (optional)"; fi

format: venv
	$(VENV)/bin/ruff format core/ ml/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
