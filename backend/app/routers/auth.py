from fastapi import APIRouter, Depends, HTTPException
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


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest) -> LoginResponse:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT username, password_hash, role, tenant FROM users WHERE username = $1",
                                  body.username)
    if not check_login(body.password, row["password_hash"] if row else None):
        # One message for "no such user" and "wrong password": don't reveal which usernames exist.
        raise HTTPException(401, "invalid username or password")
    claims = Claims(sub=row["username"], role=row["role"], tenant=row["tenant"])
    return LoginResponse(access_token=create_token(claims), expires_in=settings.jwt_expire_minutes * 60, user=claims)


@router.get("/me", response_model=Claims)
async def me(user: Claims = Depends(current_user)) -> Claims:
    return user
