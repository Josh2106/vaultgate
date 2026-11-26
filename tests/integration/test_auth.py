from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pyotp
import pytest
from sqlalchemy import select

from app.db.models import RefreshToken, User
from app.state import AppState
from tests.conftest import PASSWORD, bearer, last_token_for, outbox, register

pytestmark = pytest.mark.asyncio


async def test_signup_verify_login_me(client: httpx.AsyncClient, state: AppState) -> None:
    u = await register(client, state, "alice@example.com")
    r = await client.get("/api/v1/users/me", headers=u.headers)
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert body["email_verified"] is True
    assert body["mfa_enabled"] is False
    assert "password_hash" not in body


async def test_signup_is_enumeration_resistant(client: httpx.AsyncClient, state: AppState) -> None:
    payload = {"email": "bob@example.com", "password": PASSWORD}
    first = await client.post("/api/v1/auth/signup", json=payload)
    second = await client.post("/api/v1/auth/signup", json=payload)
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()
    subjects = [m.subject for m in outbox(state).outbox if m.to == "bob@example.com"]
    assert subjects[-1].startswith("Sign-up attempt")


async def test_email_is_normalised(client: httpx.AsyncClient, state: AppState) -> None:
    await register(client, state, "Carol@Example.com")
    r = await client.post(
        "/api/v1/auth/login", json={"email": "carol@example.COM", "password": PASSWORD}
    )
    assert r.status_code == 200


@pytest.mark.parametrize(
    ("password", "fragment"),
    [
        ("short1A!", "at least 12"),
        ("aaaaaaaaaaaaaaaa", "distinct"),
        ("alllowercaseletters", "mix at least two"),
        ("password1234", "too common"),
        ("dave-the-user-Pass1", "email"),
    ],
)
async def test_password_policy(client: httpx.AsyncClient, password: str, fragment: str) -> None:
    r = await client.post(
        "/api/v1/auth/signup", json={"email": "dave-the-user@example.com", "password": password}
    )
    assert r.status_code == 422
    assert r.headers["content-type"] == "application/problem+json"
    msgs = " ".join(e["msg"] for e in r.json()["errors"])
    assert fragment in msgs


async def test_unknown_fields_rejected(client: httpx.AsyncClient) -> None:
    r = await client.post(
        "/api/v1/auth/signup",
        json={"email": "e@example.com", "password": PASSWORD, "is_admin": True},
    )
    assert r.status_code == 422


async def test_invalid_login_is_generic_problem(client: httpx.AsyncClient, state: AppState) -> None:
    await register(client, state, "frank@example.com")
    wrong = await client.post(
        "/api/v1/auth/login", json={"email": "frank@example.com", "password": "Wrong-password-1"}
    )
    unknown = await client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}
    )
    for r in (wrong, unknown):
        assert r.status_code == 401
        assert r.headers["content-type"] == "application/problem+json"
        assert r.json()["type"] == "urn:vaultgate:problem:invalid-credentials"
        assert r.headers["www-authenticate"] == "Bearer"
    assert wrong.json()["detail"] == unknown.json()["detail"]


async def test_account_lockout(client: httpx.AsyncClient, state: AppState) -> None:
    await register(client, state, "gina@example.com")
    for _ in range(state.settings.lockout_threshold):
        r = await client.post(
            "/api/v1/auth/login", json={"email": "gina@example.com", "password": "Wrong-password-1"}
        )
        assert r.status_code == 401
    # Correct password is now refused, with the same generic response.
    r = await client.post(
        "/api/v1/auth/login", json={"email": "gina@example.com", "password": PASSWORD}
    )
    assert r.status_code == 401
    assert r.json()["type"].endswith("invalid-credentials")

    # After the lockout expires the user can log in again.
    async with state.sessionmaker() as s:
        user = (await s.execute(select(User).where(User.email == "gina@example.com"))).scalar_one()
        assert user.locked_until is not None
        user.locked_until = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()
    r = await client.post(
        "/api/v1/auth/login", json={"email": "gina@example.com", "password": PASSWORD}
    )
    assert r.status_code == 200


async def test_refresh_rotation(client: httpx.AsyncClient, state: AppState) -> None:
    u = await register(client, state)
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": u.refresh})
    assert r.status_code == 200
    new = r.json()
    assert new["refresh_token"] != u.refresh
    me = await client.get("/api/v1/users/me", headers=bearer(new["access_token"]))
    assert me.status_code == 200
    # The rotated token works again exactly once more (it is the newest in the family).
    r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": new["refresh_token"]})
    assert r2.status_code == 200


async def test_refresh_reuse_revokes_whole_family(
    client: httpx.AsyncClient, state: AppState
) -> None:
    u = await register(client, state)
    stolen = u.refresh
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})
    legit_next = r.json()["refresh_token"]

    # Attacker replays the old (already rotated) token -> reuse detected.
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})
    assert r.status_code == 401
    assert "reuse" in r.json()["detail"].lower()

    # The legitimate client's *newer* token is now dead too: the family was revoked.
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": legit_next})
    assert r.status_code == 401

    async with state.sessionmaker() as s:
        rows = (
            (await s.execute(select(RefreshToken).where(RefreshToken.user_id == u.id)))
            .scalars()
            .all()
        )
        assert rows and all(t.revoked_at is not None for t in rows)
        assert {t.revoke_reason for t in rows} == {"reuse_detected"}


async def test_refresh_unknown_and_expired(client: httpx.AsyncClient, state: AppState) -> None:
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": "vgr_doesnotexist"})
    assert r.status_code == 401
    u = await register(client, state)
    async with state.sessionmaker() as s:
        for t in (
            await s.execute(select(RefreshToken).where(RefreshToken.user_id == u.id))
        ).scalars():
            t.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": u.refresh})
    assert r.status_code == 401


async def test_logout_revokes_family(client: httpx.AsyncClient, state: AppState) -> None:
    u = await register(client, state)
    r = await client.post("/api/v1/auth/logout", json={"refresh_token": u.refresh})
    assert r.status_code == 204
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": u.refresh})
    assert r.status_code == 401
    # Logging out an unknown token is a silent no-op.
    r = await client.post("/api/v1/auth/logout", json={"refresh_token": "vgr_unknown-token"})
    assert r.status_code == 204


async def test_logout_all_kills_access_tokens(client: httpx.AsyncClient, state: AppState) -> None:
    u = await register(client, state)
    r = await client.post("/api/v1/auth/logout-all", headers=u.headers)
    assert r.status_code == 204
    # JWT iat has 1s resolution; shift the cutoff so the token is strictly older.
    async with state.sessionmaker() as s:
        user = await s.get(User, u.id)
        assert user is not None and user.tokens_valid_after is not None
        user.tokens_valid_after = user.tokens_valid_after + timedelta(seconds=1)
        await s.commit()
    r = await client.get("/api/v1/users/me", headers=u.headers)
    assert r.status_code == 401
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": u.refresh})
    assert r.status_code == 401


async def test_change_password(client: httpx.AsyncClient, state: AppState) -> None:
    u = await register(client, state, "hank@example.com")
    r = await client.post(
        "/api/v1/auth/password/change",
        headers=u.headers,
        json={"current_password": "nope-nope-nope", "new_password": "x"},
    )
    assert r.status_code == 401
    r = await client.post(
        "/api/v1/auth/password/change",
        headers=u.headers,
        json={"current_password": PASSWORD, "new_password": PASSWORD},
    )
    assert r.status_code == 422
    r = await client.post(
        "/api/v1/auth/password/change",
        headers=u.headers,
        json={"current_password": PASSWORD, "new_password": "Brand-New-Passphrase-7"},
    )
    assert r.status_code == 204
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": u.refresh})
    assert r.status_code == 401
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "hank@example.com", "password": "Brand-New-Passphrase-7"},
    )
    assert r.status_code == 200


async def test_oauth2_token_endpoint(client: httpx.AsyncClient, state: AppState) -> None:
    await register(client, state, "ivy@example.com")
    r = await client.post(
        "/api/v1/auth/token", data={"username": "ivy@example.com", "password": PASSWORD}
    )
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"


async def test_unverified_user_cannot_create_org(
    client: httpx.AsyncClient, state: AppState
) -> None:
    u = await register(client, state, "jack@example.com", verify=False)
    r = await client.post("/api/v1/orgs", json={"name": "X", "slug": "xx"}, headers=u.headers)
    assert r.status_code == 403
    assert r.json()["type"].endswith("email-not-verified")
    r = await client.post("/api/v1/auth/verify-email/resend", headers=u.headers)
    assert r.status_code == 202
    token = last_token_for(state, "jack@example.com")
    assert (
        await client.post("/api/v1/auth/verify-email", json={"token": token})
    ).status_code == 204
    # Tokens are single-use.
    assert (
        await client.post("/api/v1/auth/verify-email", json={"token": token})
    ).status_code == 401
    r = await client.post("/api/v1/orgs", json={"name": "X", "slug": "xx"}, headers=u.headers)
    assert r.status_code == 201
    # Resend for a verified user is a no-op.
    assert (
        await client.post("/api/v1/auth/verify-email/resend", headers=u.headers)
    ).status_code == 202


async def test_bad_bearer_tokens(client: httpx.AsyncClient) -> None:
    for token in ("garbage", "a.b.c", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."):
        r = await client.get("/api/v1/users/me", headers=bearer(token))
        assert r.status_code == 401
    r = await client.get("/api/v1/users/me")
    assert r.status_code == 401


async def test_totp_full_lifecycle(client: httpx.AsyncClient, state: AppState) -> None:
    u = await register(client, state, "kim@example.com")
    r = await client.post("/api/v1/auth/2fa/setup", headers=u.headers)
    assert r.status_code == 200
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/")
    totp = pyotp.TOTP(secret)

    assert (
        await client.post("/api/v1/auth/2fa/enable", headers=u.headers, json={"code": "000000"})
    ).status_code == 422
    enabled_at = datetime.now(UTC)
    r = await client.post(
        "/api/v1/auth/2fa/enable", headers=u.headers, json={"code": totp.at(enabled_at)}
    )
    assert r.status_code == 200
    codes = r.json()["recovery_codes"]
    assert len(codes) == 10
    assert (await client.post("/api/v1/auth/2fa/setup", headers=u.headers)).status_code == 409

    # Password login now yields an MFA challenge rather than tokens.
    r = await client.post("/api/v1/auth/login", json={"email": u.email, "password": PASSWORD})
    assert r.status_code == 200
    challenge = r.json()
    assert challenge["mfa_required"] is True
    assert "access_token" not in challenge
    # OAuth2 form flow cannot complete MFA.
    r = await client.post("/api/v1/auth/token", data={"username": u.email, "password": PASSWORD})
    assert r.status_code == 401 and r.json()["type"].endswith("mfa-required")

    # The same TOTP code used for enable cannot be replayed (counter must advance).
    code_used = totp.at(enabled_at)
    r = await client.post(
        "/api/v1/auth/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": code_used}
    )
    assert r.status_code == 401

    # Next time-step code works.
    future = totp.at(enabled_at + timedelta(seconds=30))
    r = await client.post(
        "/api/v1/auth/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": future}
    )
    assert r.status_code == 200, r.text
    assert "access_token" in r.json()

    # A recovery code works exactly once.
    r = await client.post(
        "/api/v1/auth/login/mfa",
        json={"mfa_token": challenge["mfa_token"], "code": codes[0].lower()},
    )
    assert r.status_code == 200
    r = await client.post(
        "/api/v1/auth/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": codes[0]}
    )
    assert r.status_code == 401

    # An access token is not an MFA token.
    r = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": u.access, "code": codes[1]})
    assert r.status_code == 401

    # Disable requires password + a valid second factor.
    r = await client.post(
        "/api/v1/auth/2fa/disable",
        headers=u.headers,
        json={"password": "wrong-password!", "code": codes[1]},
    )
    assert r.status_code == 401
    r = await client.post(
        "/api/v1/auth/2fa/disable", headers=u.headers, json={"password": PASSWORD, "code": "999999"}
    )
    assert r.status_code == 401
    r = await client.post(
        "/api/v1/auth/2fa/disable", headers=u.headers, json={"password": PASSWORD, "code": codes[1]}
    )
    assert r.status_code == 204
    assert (
        await client.post(
            "/api/v1/auth/2fa/disable",
            headers=u.headers,
            json={"password": PASSWORD, "code": codes[2]},
        )
    ).status_code == 409
    r = await client.post("/api/v1/auth/login", json={"email": u.email, "password": PASSWORD})
    assert "access_token" in r.json()


async def test_totp_enable_requires_setup(client: httpx.AsyncClient, state: AppState) -> None:
    u = await register(client, state)
    r = await client.post("/api/v1/auth/2fa/enable", headers=u.headers, json={"code": "123456"})
    assert r.status_code == 422


async def test_jwks_and_key_rotation(client: httpx.AsyncClient, state: AppState) -> None:
    from app.core.tokens import KeyRing, generate_private_key_pem

    u = await register(client, state)
    old_kid = state.tokens.keyring.active_kid
    (state.settings.jwt_keys_dir / "29991231-newkey00.pem").write_bytes(generate_private_key_pem())
    state.tokens.keyring = KeyRing.from_directory(state.settings.jwt_keys_dir)
    assert state.tokens.keyring.active_kid == "29991231-newkey00"

    jwks = (await client.get("/.well-known/jwks.json")).json()
    assert {k["kid"] for k in jwks["keys"]} == {old_kid, "29991231-newkey00"}
    assert all(k["kty"] == "OKP" and k["alg"] == "EdDSA" for k in jwks["keys"])

    # Token signed by the previous key still verifies during the overlap window.
    assert (await client.get("/api/v1/users/me", headers=u.headers)).status_code == 200
    # Retire the old key: its tokens stop verifying.
    (state.settings.jwt_keys_dir / f"{old_kid}.pem").unlink()
    state.tokens.keyring = KeyRing.from_directory(state.settings.jwt_keys_dir)
    assert (await client.get("/api/v1/users/me", headers=u.headers)).status_code == 401
