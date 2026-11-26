"""Client address resolution that is safe behind (and only behind) trusted proxies."""

from __future__ import annotations

from starlette.types import Scope


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return str(value.decode("latin-1"))
    return None


def client_ip(scope: Scope, trusted_hops: int = 0) -> str:
    """Return the client IP.

    ``X-Forwarded-For`` is attacker-controlled unless we know exactly how many
    proxies we sit behind. With ``trusted_hops = N`` we take the N-th address
    from the right - the one appended by our outermost trusted proxy - and ignore
    anything the client prepended.
    """
    if trusted_hops > 0:
        xff = _header(scope, b"x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[-trusted_hops] if len(parts) >= trusted_hops else parts[0]
    client = scope.get("client")
    return str(client[0]) if client else "unknown"


def header(scope: Scope, name: str) -> str | None:
    return _header(scope, name.lower().encode("latin-1"))
