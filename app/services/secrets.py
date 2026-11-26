"""Versioned, envelope-encrypted secrets."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import DecryptionError, EncryptedPayload
from app.core.errors import AppError, Conflict, NotFound
from app.db.base import utcnow
from app.db.models import Secret, SecretVersion
from app.services import audit
from app.services.context import OrgAccess
from app.services.pagination import Page, paginate_by_time
from app.services.projects import get_project
from app.state import AppState


class SecretIntegrityError(AppError):
    status_code, slug, title = 500, "secret-integrity", "Secret failed integrity verification"


def secret_aad(secret_id: uuid.UUID, version: int) -> bytes:
    """Bind ciphertext to its row so it cannot be transplanted to another secret/version."""
    return f"vaultgate:secret:{secret_id}:v{version}".encode()


@dataclass(slots=True)
class DecryptedSecret:
    secret: Secret
    version: int
    value: str


async def _get_secret(
    session: AsyncSession, project_id: uuid.UUID, name: str, *, include_deleted: bool = False
) -> Secret:
    secret = (
        await session.execute(
            select(Secret).where(Secret.project_id == project_id, Secret.name == name)
        )
    ).scalar_one_or_none()
    if secret is None or (secret.deleted_at is not None and not include_deleted):
        raise NotFound("Secret not found.")
    return secret


def _encrypt_version(
    state: AppState, access: OrgAccess, secret_id: uuid.UUID, version: int, value: str
) -> SecretVersion:
    payload = state.cipher.encrypt(value.encode("utf-8"), secret_aad(secret_id, version))
    return SecretVersion(
        secret_id=secret_id,
        version=version,
        ciphertext=payload.ciphertext,
        wrapped_dek=payload.wrapped_dek,
        master_key_id=payload.key_id,
        created_by_type=access.principal.actor_type.value,
        created_by_id=access.principal.actor_id,
    )


async def create_secret(
    state: AppState,
    session: AsyncSession,
    access: OrgAccess,
    project_id: uuid.UUID,
    *,
    name: str,
    value: str,
) -> Secret:
    project = await get_project(session, access.org_id, project_id)
    existing = (
        await session.execute(
            select(Secret.id).where(Secret.project_id == project.id, Secret.name == name)
        )
    ).first()
    if existing is not None:
        raise Conflict(f"Secret {name!r} already exists (it may be soft-deleted; restore it).")
    secret = Secret(id=uuid.uuid4(), project_id=project.id, name=name, current_version=1)
    session.add(secret)
    session.add(_encrypt_version(state, access, secret.id, 1, value))
    await session.flush()
    await audit.record(
        session,
        access.ctx,
        "secret.created",
        org_id=access.org_id,
        target_type="secret",
        target_id=secret.id,
        details={"project_id": str(project.id), "name": name, "version": 1},
    )
    await session.commit()
    state.metrics.secret_ops.labels(op="create").inc()
    return secret


async def list_secrets(
    session: AsyncSession,
    access: OrgAccess,
    project_id: uuid.UUID,
    *,
    limit: int | None,
    cursor: str | None,
    include_deleted: bool = False,
) -> Page[Secret]:
    project = await get_project(session, access.org_id, project_id)
    stmt = select(Secret).where(Secret.project_id == project.id)
    if not include_deleted:
        stmt = stmt.where(Secret.deleted_at.is_(None))
    return await paginate_by_time(
        session, stmt, Secret.created_at, Secret.id, limit=limit, cursor=cursor
    )


async def read_secret(
    state: AppState,
    session: AsyncSession,
    access: OrgAccess,
    project_id: uuid.UUID,
    name: str,
    *,
    version: int | None = None,
) -> DecryptedSecret:
    project = await get_project(session, access.org_id, project_id)
    secret = await _get_secret(session, project.id, name)
    wanted = version or secret.current_version
    row = (
        await session.execute(
            select(SecretVersion).where(
                SecretVersion.secret_id == secret.id, SecretVersion.version == wanted
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFound(f"Version {wanted} does not exist.")
    try:
        plaintext = state.cipher.decrypt(
            EncryptedPayload(row.ciphertext, row.wrapped_dek, row.master_key_id),
            secret_aad(secret.id, row.version),
        )
    except DecryptionError as exc:
        # Integrity failure = tampering or lost key. Audit it and fail closed.
        await audit.record(
            session,
            access.ctx,
            "secret.decrypt_failed",
            org_id=access.org_id,
            target_type="secret",
            target_id=secret.id,
            details={"version": wanted},
        )
        await session.commit()
        raise SecretIntegrityError() from exc
    # Reads of secret *values* are security-relevant and audited like mutations.
    await audit.record(
        session,
        access.ctx,
        "secret.read",
        org_id=access.org_id,
        target_type="secret",
        target_id=secret.id,
        details={"version": wanted},
    )
    await session.commit()
    state.metrics.secret_ops.labels(op="read").inc()
    return DecryptedSecret(secret, wanted, plaintext.decode("utf-8"))


async def update_secret(
    state: AppState,
    session: AsyncSession,
    access: OrgAccess,
    project_id: uuid.UUID,
    name: str,
    *,
    value: str,
) -> Secret:
    project = await get_project(session, access.org_id, project_id)
    secret = await _get_secret(session, project.id, name)
    new_version = secret.current_version + 1
    session.add(_encrypt_version(state, access, secret.id, new_version, value))
    secret.current_version = new_version
    secret.updated_at = utcnow()
    await audit.record(
        session,
        access.ctx,
        "secret.updated",
        org_id=access.org_id,
        target_type="secret",
        target_id=secret.id,
        details={"version": new_version},
    )
    await session.commit()
    state.metrics.secret_ops.labels(op="update").inc()
    return secret


async def list_versions(
    session: AsyncSession, access: OrgAccess, project_id: uuid.UUID, name: str
) -> list[SecretVersion]:
    project = await get_project(session, access.org_id, project_id)
    secret = await _get_secret(session, project.id, name)
    rows = await session.execute(
        select(SecretVersion)
        .where(SecretVersion.secret_id == secret.id)
        .order_by(SecretVersion.version.desc())
    )
    return list(rows.scalars())


async def delete_secret(
    session: AsyncSession, access: OrgAccess, project_id: uuid.UUID, name: str
) -> None:
    project = await get_project(session, access.org_id, project_id)
    secret = await _get_secret(session, project.id, name)
    secret.deleted_at = utcnow()
    await audit.record(
        session,
        access.ctx,
        "secret.deleted",
        org_id=access.org_id,
        target_type="secret",
        target_id=secret.id,
    )
    await session.commit()


async def restore_secret(
    session: AsyncSession, access: OrgAccess, project_id: uuid.UUID, name: str
) -> Secret:
    project = await get_project(session, access.org_id, project_id)
    secret = await _get_secret(session, project.id, name, include_deleted=True)
    if secret.deleted_at is None:
        raise Conflict("Secret is not deleted.")
    secret.deleted_at = None
    await audit.record(
        session,
        access.ctx,
        "secret.restored",
        org_id=access.org_id,
        target_type="secret",
        target_id=secret.id,
    )
    await session.commit()
    return secret


async def rewrap_all(state: AppState, session: AsyncSession, batch: int = 200) -> int:
    """Re-wrap every DEK not under the active master key. Returns rows changed."""
    active = state.cipher.provider.active_key_id
    changed = 0
    while True:
        rows = (
            (
                await session.execute(
                    select(SecretVersion).where(SecretVersion.master_key_id != active).limit(batch)
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            break
        for row in rows:
            payload = state.cipher.rewrap(
                EncryptedPayload(row.ciphertext, row.wrapped_dek, row.master_key_id),
                secret_aad(row.secret_id, row.version),
            )
            row.wrapped_dek = payload.wrapped_dek
            row.master_key_id = payload.key_id
            changed += 1
        await session.commit()
    return changed
