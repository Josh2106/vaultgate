"""Operator CLI: ``vaultgate <command>`` (or ``python -m app.cli``)."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.core.crypto import EncryptedPayload, LocalKeyProvider
from app.core.tokens import generate_private_key_pem, new_kid
from app.db.base import Base
from app.db.models import User
from app.services import audit
from app.services.auth import totp_aad
from app.services.secrets import rewrap_all
from app.state import AppState


async def _verify_audit_chain(settings: Settings) -> int:
    state = AppState.build(settings)
    try:
        async with state.sessionmaker() as session:
            result = await audit.verify_chain(session)
    finally:
        await state.aclose()
    if result.ok:
        print(f"OK: audit chain intact ({result.checked} events verified)")
        return 0
    print(
        f"TAMPERING DETECTED at seq={result.first_bad_seq}: {result.reason} "
        f"({result.checked} events verified before the break)",
        file=sys.stderr,
    )
    return 2


async def _init_db(settings: Settings) -> int:
    state = AppState.build(settings)
    try:
        async with state.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    finally:
        await state.aclose()
    print("database schema created (use `alembic upgrade head` for real deployments)")
    return 0


async def _rewrap(settings: Settings) -> int:
    state = AppState.build(settings)
    try:
        async with state.sessionmaker() as session:
            secrets_changed = await rewrap_all(state, session)
            users = (
                (await session.execute(select(User).where(User.totp_secret_enc.is_not(None))))
                .scalars()
                .all()
            )
            totp_changed = 0
            for user in users:
                assert user.totp_secret_enc is not None  # noqa: S101
                old = EncryptedPayload.from_blob(user.totp_secret_enc)
                new = state.cipher.rewrap(old, totp_aad(user.id))
                if new is not old:
                    user.totp_secret_enc = new.to_blob()
                    totp_changed += 1
            await session.commit()
    finally:
        await state.aclose()
    print(
        f"re-wrapped {secrets_changed} secret versions and {totp_changed} TOTP seeds "
        f"under {state.cipher.provider.active_key_id}"
    )
    return 0


def _rotate_master_key(settings: Settings) -> int:
    path = settings.master_key_file
    provider = LocalKeyProvider.load(path, auto_generate=False)
    rotated = provider.with_new_active_key()
    rotated.save(path)
    print(
        f"new active master key {rotated.active_key_id}; previous keys retained. "
        "Restart the API, then run `vaultgate rewrap-secrets`."
    )
    return 0


def _generate_jwt_key(directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    kid = new_kid()
    path = directory / f"{kid}.pem"
    path.write_bytes(generate_private_key_pem())
    path.chmod(0o600)
    print(
        f"wrote {path} (kid={kid}). It becomes active if it is the newest kid "
        "or when VG_JWT_ACTIVE_KID is set to it."
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vaultgate", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify-audit-chain", help="Recompute the audit hash chain; exit 2 on tamper")
    sub.add_parser("init-db", help="Create tables directly (development only)")
    sub.add_parser("rotate-master-key", help="Add a new active master key to the key file")
    sub.add_parser("rewrap-secrets", help="Re-wrap all DEKs under the active master key")
    g = sub.add_parser("generate-jwt-key", help="Create a new Ed25519 signing key")
    g.add_argument("--dir", type=Path, default=None)
    args = parser.parse_args(argv)

    settings = get_settings()
    match args.command:
        case "verify-audit-chain":
            return asyncio.run(_verify_audit_chain(settings))
        case "init-db":
            return asyncio.run(_init_db(settings))
        case "rotate-master-key":
            return _rotate_master_key(settings)
        case "rewrap-secrets":
            return asyncio.run(_rewrap(settings))
        case "generate-jwt-key":
            return _generate_jwt_key(args.dir or settings.jwt_keys_dir)
    return 1  # pragma: no cover - argparse enforces a valid command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
