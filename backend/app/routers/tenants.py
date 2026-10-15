"""Customer onboarding for admins (the website's "Tenants" page).

A tenant has no table of its own: it exists once it has a user or an API key (the same rule as the
tenant menu, `GET /api/tenants`). So adding a tenant = creating its first API key, which is also
what it needs to start sending logs. Adding a viewer gives one of the customer's staff a sign-in
that can only ever see that tenant (the JWT carries it, and `resolve_tenant` enforces it).
"""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import db
from ..api_keys import create_key
from ..auth import hash_password, require_admin

router = APIRouter(prefix="/api/admin/tenants", tags=["tenants"], dependencies=[Depends(require_admin)])

# Letters, digits, "_" and "-", starting with a letter: safe in URLs (?tenant=) and readable.
NAME = r"^[A-Za-z][A-Za-z0-9_-]{1,31}$"


class NewTenant(BaseModel):
    name: str = Field(pattern=NAME, description='e.g. "acme" or "demoC"')


class NewViewer(BaseModel):
    username: str = Field(pattern=NAME)
    password: str = Field(min_length=12, max_length=128)


async def _tenant_exists(conn, name: str) -> bool:
    # Case-insensitive, so "demoa" can't be created next to "demoA" and be mixed up.
    return await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM users WHERE lower(tenant) = lower($1) "
        "UNION ALL SELECT 1 FROM api_keys WHERE lower(tenant) = lower($1))", name)


@router.get("")
async def list_tenants() -> list[dict[str, Any]]:
    """Every tenant with its viewers and number of active API keys."""
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT t.tenant,
                      coalesce((SELECT array_agg(username ORDER BY username) FROM users
                                WHERE tenant = t.tenant AND role = 'viewer'), '{}') AS viewers,
                      (SELECT count(*) FROM api_keys WHERE tenant = t.tenant AND revoked_at IS NULL) AS keys
               FROM (SELECT tenant FROM users UNION SELECT tenant FROM api_keys) t
               ORDER BY lower(t.tenant)""")
    return [{"tenant": r["tenant"], "viewers": list(r["viewers"]), "active_keys": r["keys"]} for r in rows]


@router.post("", status_code=201)
async def add_tenant(body: NewTenant) -> dict[str, Any]:
    """Creates the tenant with its first API key. The key is in this response only (stored hashed)."""
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            if await _tenant_exists(conn, body.name):
                raise HTTPException(409, f"tenant {body.name!r} already exists")
            key = await create_key(conn, body.name, "first key")
    return {"tenant": body.name, "key": key}


@router.post("/{tenant}/viewers", status_code=201)
async def add_viewer(tenant: str, body: NewViewer) -> dict[str, Any]:
    """A sign-in for the customer's staff: read-only, and only this tenant."""
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            if not await conn.fetchval(
                    "SELECT EXISTS (SELECT 1 FROM users WHERE tenant = $1 "
                    "UNION ALL SELECT 1 FROM api_keys WHERE tenant = $1)", tenant):
                raise HTTPException(404, f"unknown tenant {tenant!r}")
            # Case-insensitive too: "viewera" next to "viewerA" would be confusing at sign-in.
            if await conn.fetchval("SELECT EXISTS (SELECT 1 FROM users WHERE lower(username) = lower($1))", body.username):
                raise HTTPException(409, f"username {body.username!r} is taken")
            await conn.execute(
                "INSERT INTO users (username, password_hash, role, tenant) VALUES ($1, $2, 'viewer', $3)",
                body.username, hash_password(body.password), tenant)
    return {"username": body.username, "role": "viewer", "tenant": tenant}
