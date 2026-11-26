# Unix-ish entry points. Windows users: see scripts/tasks.ps1 (same targets).
PY ?= python
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: help install lint fmt typecheck test cov run migrate verify-audit lock docker-build compose-up compose-down clean

help:  ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-14s %s\n", $$1, $$2}'

install:  ## Create venv and install pinned dev dependencies
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -r requirements-dev.lock
	$(BIN)/pip install --no-deps -e .
	$(BIN)/pre-commit install

lint:  ## Ruff lint + format check
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

fmt:  ## Auto-format
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

typecheck:  ## mypy --strict
	$(BIN)/mypy

test:  ## Run the test suite in parallel
	$(BIN)/pytest -n auto

cov:  ## Tests with coverage report
	$(BIN)/pytest -n auto --cov=app --cov-report=term-missing --cov-report=html

run:  ## Dev server (SQLite, auto-generated dev keys, Swagger at /docs)
	$(BIN)/alembic upgrade head
	VG_LOG_JSON=false $(BIN)/uvicorn app.main:app_factory --factory --reload

migrate:  ## Apply migrations
	$(BIN)/alembic upgrade head

verify-audit:  ## Verify the audit hash chain
	$(BIN)/vaultgate verify-audit-chain

lock:  ## Re-pin dependencies
	uv pip compile pyproject.toml --python-version 3.12 --python-platform linux --generate-hashes -o requirements.lock
	uv pip compile pyproject.toml --extra dev --python-version 3.12 --python-platform linux -o requirements-dev.lock

docker-build:  ## Build the production image
	docker build -t vaultgate:local .

compose-up:  ## Full stack: api, postgres, redis, otel, prometheus, grafana
	docker compose up --build -d

compose-down:
	docker compose down -v

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .hypothesis htmlcov .coverage*
