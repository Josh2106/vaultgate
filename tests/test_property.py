"""Property-based tests (Hypothesis).

Includes two API-level properties driven through the real ASGI stack:

* any Unicode secret value survives create -> update -> read byte-for-byte;
* arbitrary JSON thrown at the signup endpoint never produces a 5xx and every
  error is RFC 7807 problem+json (a lightweight, schema-agnostic fuzz).
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.core.crypto import EnvelopeCipher, LocalKeyProvider
from app.core.permissions import Role
from app.main import create_app
from app.services.pagination import decode_time_cursor, encode_time_cursor
from tests.conftest import World, build_world, make_settings, start_app

_cipher = EnvelopeCipher(LocalKeyProvider.generate())


@given(plaintext=st.binary(max_size=4096), aad=st.binary(max_size=256))
def test_envelope_roundtrip(plaintext: bytes, aad: bytes) -> None:
    assert _cipher.decrypt(_cipher.encrypt(plaintext, aad), aad) == plaintext


@given(ts=st.datetimes(timezones=st.just(UTC)), rid=st.uuids())
def test_cursor_roundtrip(ts: datetime, rid: uuid.UUID) -> None:
    assert decode_time_cursor(encode_time_cursor(ts, rid)) == (ts, rid)


class _Harness:
    """Run an app on a private event loop so sync Hypothesis tests can drive it."""

    def __init__(self, tmp_path: Path) -> None:
        self.loop = asyncio.new_event_loop()
        self.app = create_app(make_settings(tmp_path))
        self._lifespan = start_app(self.app)
        self.state = self.run(self._lifespan.__anext__())
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://test"
        )

    def run(self, coro: Any) -> Any:
        return self.loop.run_until_complete(coro)

    def close(self) -> None:
        self.run(self.client.aclose())
        with pytest.raises(StopAsyncIteration):
            self.run(self._lifespan.__anext__())
        self.loop.close()


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[_Harness]:
    h = _Harness(tmp_path)
    try:
        yield h
    finally:
        h.close()


def test_secret_values_roundtrip_through_api(harness: _Harness) -> None:
    world: World = harness.run(build_world(harness.client, harness.state))
    headers = world.users[Role.MEMBER].headers
    base = f"{world.base()}/projects/{world.project_id}/secrets"
    counter = iter(range(10_000))

    @settings(
        max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    @given(first=st.text(min_size=1, max_size=300), second=st.text(min_size=1, max_size=300))
    def prop(first: str, second: str) -> None:
        name = f"PROP_{next(counter)}"

        async def scenario() -> None:
            c = harness.client
            r = await c.post(base, json={"name": name, "value": first}, headers=headers)
            assert r.status_code == 201, r.text
            r = await c.put(f"{base}/{name}", json={"value": second}, headers=headers)
            assert r.status_code == 200, r.text
            latest = (await c.get(f"{base}/{name}", headers=headers)).json()
            v1 = (await c.get(f"{base}/{name}", params={"version": 1}, headers=headers)).json()
            assert latest["value"] == second and v1["value"] == first

        harness.run(scenario())

    prop()


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=50),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=10), children, max_size=4)
    ),
    max_leaves=10,
)
signup_like = st.fixed_dictionaries(
    {},
    optional={
        "email": st.one_of(st.emails(), st.text(max_size=40)),
        "password": st.text(max_size=140),
        "full_name": json_values,
        "extra": json_values,
    },
)


def test_signup_never_500s(harness: _Harness) -> None:
    @settings(
        max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    @given(body=st.one_of(signup_like, json_values))
    def prop(body: Any) -> None:
        r: httpx.Response = harness.run(harness.client.post("/api/v1/auth/signup", json=body))
        assert r.status_code < 500, r.text
        if r.status_code >= 400:
            assert r.headers["content-type"] == "application/problem+json"
            assert r.json()["status"] == r.status_code

    prop()
