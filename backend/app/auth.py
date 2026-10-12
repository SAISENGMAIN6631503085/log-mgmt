"""Login (JWT) and the tenant rules every protected endpoint relies on.

Tokens carry sub (username), role (admin|viewer) and tenant. They are stateless: the server
doesn't look the user up on each request, so a role change applies when the token expires
(JWT_EXPIRE_MINUTES). That's the usual trade-off for not hitting the DB on every call.
"""
from datetime import datetime, timedelta, timezone
from typing import Literal

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from .config import settings

ALGORITHM = "HS256"
_PLACEHOLDER_SECRET = "change-me-to-a-long-random-string"


def check_jwt_secret() -> None:
    """Called at startup: a weak or example secret would let anyone forge admin tokens."""
    s = settings.jwt_secret
    if len(s) < 32 or s == _PLACEHOLDER_SECRET:
        raise RuntimeError("JWT_SECRET must be set to a random string of at least 32 chars "
                           "(e.g. `openssl rand -hex 32`)")


# --- passwords ---------------------------------------------------------------

def hash_password(password: str) -> str:
    # bcrypt is deliberately slow and salts each hash, so stolen hashes are hard to crack.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


# Used when the username doesn't exist, so a failed login takes the same time either way
# and response timing can't reveal which usernames are real.
_DUMMY_HASH = hash_password("timing-equaliser")


def check_login(password: str, password_hash: str | None) -> bool:
    ok = verify_password(password, password_hash or _DUMMY_HASH)
    return ok and password_hash is not None


# --- tokens ------------------------------------------------------------------

class Claims(BaseModel):
    sub: str
    role: Literal["admin", "viewer"]
    tenant: str


def create_token(claims: Claims, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    payload = claims.model_dump() | {"iat": now, "exp": now + timedelta(minutes=settings.jwt_expire_minutes)}
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def decode_token(token: str) -> Claims:
    try:
        # algorithms is pinned: never let the token's own header pick the algorithm ("alg": "none").
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM],
                             options={"require": ["exp", "sub", "role", "tenant"]})
        return Claims(**{k: payload[k] for k in ("sub", "role", "tenant")})
    except (jwt.InvalidTokenError, ValueError):
        raise HTTPException(401, "invalid or expired token", headers={"WWW-Authenticate": "Bearer"}) from None


_bearer = HTTPBearer(auto_error=False)


async def current_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Claims:
    if creds is None:
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    return decode_token(creds.credentials)


async def require_admin(user: Claims = Depends(current_user)) -> Claims:
    if user.role != "admin":
        raise HTTPException(403, "admin only")
    return user


# --- tenant scoping ----------------------------------------------------------

def resolve_tenant(user: Claims, requested: str | None) -> str:
    """The single place that decides which tenant a request may read.

    - viewer: always their own tenant from the JWT; asking for another one is 403
      (not silently ignored, so a client bug or probing attempt is visible).
    - admin: may switch with ?tenant=, defaults to their own.
    """
    if requested is None or requested == user.tenant:
        return user.tenant
    if user.role == "admin":
        return requested
    raise HTTPException(403, "viewers can only access their own tenant")


async def scoped_tenant(
    tenant: str | None = Query(default=None, description="Admin only: tenant to view"),
    user: Claims = Depends(current_user),
) -> str:
    """Dependency for data endpoints: gives the tenant to filter by. Endpoints must use this
    value in their WHERE clause and never read a tenant from anywhere else."""
    return resolve_tenant(user, tenant)
