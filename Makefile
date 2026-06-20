.PHONY: up down build test test-integration venv ensure-venv migrate doctor db-revision \
	fetch-dataset train train-quick lint format clean update-check update rollback-update

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
	$(PYTHON) -m pytest tests/ -v -m "not integration" --cov=core --cov=ml --cov=lureguard_mcp --cov-report=term-missing

test-integration: venv
	$(PYTHON) -m pytest tests/ -v -m integration

fetch-dataset: venv
	$(PYTHON) -c "from ml.dataset_loaders import ensure_true_labeled_dataset; ensure_true_labeled_dataset()"

train: venv
	$(PYTHON) -m ml.train --output-dir ml/models
	$(PYTHON) -m ml.generate_tutor_report

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
