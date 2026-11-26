"""Alembic migrations produce exactly the schema the ORM expects (no drift)."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from app.db.base import Base


def _config(url: str) -> Config:
    root = Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    cfg.attributes["configure_logger"] = False
    return cfg


def test_upgrade_downgrade_and_no_drift(tmp_path: Path) -> None:
    db = (tmp_path / "mig.db").as_posix()
    cfg = _config(f"sqlite+aiosqlite:///{db}")
    command.upgrade(cfg, "head")
    sync = create_engine(f"sqlite:///{db}")
    with sync.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
        assert diff == [], diff
        tables = set(inspect(conn).get_table_names())
        assert {"users", "secrets", "audit_events", "audit_chain_head"} <= tables
        triggers = {
            r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'"))
        }
        assert {"audit_events_no_update", "audit_events_no_delete"} <= triggers
        assert conn.execute(text("SELECT seq FROM audit_chain_head")).scalar_one() == 0
    sync.dispose()
    command.downgrade(cfg, "base")
    sync = create_engine(f"sqlite:///{db}")
    with sync.connect() as conn:
        assert set(inspect(conn).get_table_names()) <= {"alembic_version"}
    sync.dispose()


def test_offline_postgres_sql_renders(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Render the Postgres DDL without a server (catches dialect-specific mistakes)."""
    cfg = _config("postgresql+asyncpg://u:p@localhost/vaultgate")
    command.upgrade(cfg, "head", sql=True)
    sql = capsys.readouterr().out
    assert "CREATE TABLE audit_events" in sql
    assert "CREATE TRIGGER audit_events_no_mutation" in sql
    assert "UUID" in sql and "TIMESTAMP WITH TIME ZONE" in sql
