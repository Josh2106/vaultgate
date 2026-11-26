# Contributing

Thanks for your interest! Issues and pull requests are welcome.

## Setup

```bash
make install            # Linux/macOS
./scripts/tasks.ps1 install   # Windows PowerShell
```

This creates `.venv`, installs the pinned dev dependencies from
`requirements-dev.lock`, installs the package in editable mode and enables the
pre-commit hooks (ruff, mypy, gitleaks, private-key detection).

## Before you open a PR

```bash
make lint typecheck test      # or: ./scripts/tasks.ps1 lint / typecheck / test
```

* **Tests**: new behaviour needs tests; coverage must stay at or above 85 %
  (CI enforces it). Security-relevant changes need a negative test (what must be
  rejected), not only the happy path.
* **Types**: `mypy --strict` must pass. Avoid `Any` and `type: ignore` unless
  justified in a comment.
* **Migrations**: schema changes need an Alembic revision
  (`alembic revision --autogenerate -m "..."`); `tests/integration/test_migrations.py`
  fails if the models and migrations drift.
* **RBAC**: permissions are defined only in `app/core/permissions.py`. If you add
  an endpoint, add it to the matrix in `tests/integration/test_rbac.py`.
* **Audit**: every mutating service function must call `audit.record(...)`
  inside the same transaction.
* **Secrets**: never commit keys, `.env` files or databases. The pre-commit hooks
  and `.gitignore` help, but you are responsible.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
`docs:`, `test:`, `refactor:`, `build:`, `ci:`, `chore:`. Keep commits focused.

## Architecture decisions

Significant design changes should come with a short ADR in `docs/adr/`.
