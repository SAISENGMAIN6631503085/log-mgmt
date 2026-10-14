import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .. import db
from ..auth import Claims, check_login, create_token, current_user
from ..config import settings

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Claims


async def _locked_until(conn, username: str, ip: str) -> datetime | None:
    """When the account or the address may try again, or None if it isn't locked.

    Locked = the Nth most recent failure (N = the limit) is still inside the window; the lock
    ends when that failure leaves the window. Sliding, so it needs no "unlock" job.
    """
    window = timedelta(minutes=settings.login_lock_minutes)
    ends = []
    for column, value, limit in (("username", username, settings.login_max_failures),
                                 ("ip", ip, settings.login_ip_max_failures)):
        nth = await conn.fetchval(
            f"""SELECT ts FROM login_failures WHERE {column} = $1 AND ts > now() - $2::interval
                ORDER BY ts DESC OFFSET $3 LIMIT 1""", value, window, limit - 1)
        if nth is not None:
            ends.append(nth + window)
    return max(ends) if ends else None


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request) -> LoginResponse:
    # The real client address: uvicorn runs with --proxy-headers behind Caddy.
    ip = request.client.host if request.client else "unknown"
    username = body.username.strip().lower()
    async with db.pool.acquire() as conn:
        until = await _locked_until(conn, username, ip)
        if until is not None:
            wait = max(1, math.ceil((until - datetime.now(timezone.utc)).total_seconds()))
            # Same answer whether or not the account exists, so the lock reveals nothing.
            raise HTTPException(429, f"Too many failed sign-ins. Try again in {math.ceil(wait / 60)} "
                                     f"minute{'s' if wait > 60 else ''}.", headers={"Retry-After": str(wait)})
        row = await conn.fetchrow("SELECT username, password_hash, role, tenant FROM users WHERE username = $1",
                                  body.username)
        if not check_login(body.password, row["password_hash"] if row else None):
            await conn.execute("INSERT INTO login_failures (username, ip) VALUES ($1, $2)", username, ip)
            # One message for "no such user" and "wrong password": don't reveal which usernames exist.
            raise HTTPException(401, "invalid username or password")
        # A successful sign-in clears the account's count (the address's count stays).
        await conn.execute("DELETE FROM login_failures WHERE username = $1", username)
    claims = Claims(sub=row["username"], role=row["role"], tenant=row["tenant"])
    return LoginResponse(access_token=create_token(claims), expires_in=settings.jwt_expire_minutes * 60, user=claims)


@router.get("/me", response_model=Claims)
async def me(user: Claims = Depends(current_user)) -> Claims:
    return user
