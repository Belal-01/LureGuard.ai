.PHONY: up down build test train lint format clean

up:
	docker compose up -d

up-llm:
	docker compose --profile local-llm up -d

down:
	docker compose down

build:
	docker compose build

test:
	pytest tests/ -v --cov=core --cov-report=term-missing

train:
	cd ml && python train.py

lint:
	ruff check core/ tests/
	mypy core/

format:
	ruff format core/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
