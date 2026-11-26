"""Single source of truth for role-based access control.

Every authorisation decision in the API reduces to ``permission in
ROLE_PERMISSIONS[role]`` (for users) or ``permission in api_key.scopes`` (for
API keys). Keeping the matrix in one module makes it reviewable at a glance and
lets the test-suite assert the full role x permission matrix.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Role.VIEWER: 0, Role.MEMBER: 1, Role.ADMIN: 2, Role.OWNER: 3}


class Permission(StrEnum):
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"
    MEMBER_READ = "member:read"
    MEMBER_MANAGE = "member:manage"
    PROJECT_READ = "project:read"
    PROJECT_WRITE = "project:write"
    PROJECT_DELETE = "project:delete"
    SECRET_LIST = "secret:list"  # metadata only, never values
    SECRET_READ = "secret:read"  # decrypt values
    SECRET_WRITE = "secret:write"
    SECRET_DELETE = "secret:delete"
    APIKEY_READ = "apikey:read"
    APIKEY_MANAGE = "apikey:manage"
    AUDIT_READ = "audit:read"


P = Permission

_VIEWER = frozenset({P.ORG_READ, P.MEMBER_READ, P.PROJECT_READ, P.SECRET_LIST})
_MEMBER = _VIEWER | {P.SECRET_READ, P.SECRET_WRITE}
_ADMIN = _MEMBER | {
    P.ORG_UPDATE,
    P.MEMBER_MANAGE,
    P.PROJECT_WRITE,
    P.PROJECT_DELETE,
    P.SECRET_DELETE,
    P.APIKEY_READ,
    P.APIKEY_MANAGE,
    P.AUDIT_READ,
}
_OWNER = _ADMIN | {P.ORG_DELETE}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: _VIEWER,
    Role.MEMBER: frozenset(_MEMBER),
    Role.ADMIN: frozenset(_ADMIN),
    Role.OWNER: frozenset(_OWNER),
}

# Scopes an API key may carry. Identity / governance permissions are never
# delegable to a machine credential: a leaked key must not be able to add
# members, mint more keys or delete the organisation.
API_KEY_GRANTABLE: frozenset[Permission] = frozenset(
    {
        P.ORG_READ,
        P.PROJECT_READ,
        P.PROJECT_WRITE,
        P.SECRET_LIST,
        P.SECRET_READ,
        P.SECRET_WRITE,
        P.SECRET_DELETE,
        P.AUDIT_READ,
    }
)


def role_has(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]
