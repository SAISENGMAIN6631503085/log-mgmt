"""Ingest API key management for admins (the website's "API keys" page).

Keys are scoped like everything else: the tenant comes from `scoped_tenant`, so an admin
manages the keys of the tenant they're viewing, and every query filters on it.
"""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import db
from ..api_keys import create_key, hash_key
from ..auth import require_admin, scoped_tenant

router = APIRouter(prefix="/api/keys", tags=["api keys"], dependencies=[Depends(require_admin)])


class NewKey(BaseModel):
    name: str = Field(min_length=1, max_length=60, pattern=r".*\S.*", description='What uses it, e.g. "firewall-01" or "shop website"')


def _key_to_api(r) -> dict[str, Any]:
    # Never the hash, and never the full key: only the prefix, to recognise it.
    return {
        "id": r["id"],
        "name": r["name"],
        "prefix": r["key_prefix"],
        "created_at": r["created_at"].isoformat(),
        "revoked_at": r["revoked_at"].isoformat() if r["revoked_at"] else None,
    }


@router.get("")
async def list_keys(tenant: str = Depends(scoped_tenant)) -> dict[str, Any]:
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, name, key_prefix, created_at, revoked_at FROM api_keys
               WHERE tenant = $1 ORDER BY revoked_at IS NOT NULL, created_at DESC""", tenant)
    return {"tenant": tenant, "keys": [_key_to_api(r) for r in rows]}


@router.post("")
async def new_key(body: NewKey, tenant: str = Depends(scoped_tenant)) -> dict[str, Any]:
    """The full key is in this response only. It's stored as a hash, so it can't be shown again."""
    async with db.pool.acquire() as conn:
        key = await create_key(conn, tenant, body.name.strip())
        row = await conn.fetchrow(
            "SELECT id, name, key_prefix, created_at, revoked_at FROM api_keys WHERE key_hash = $1", hash_key(key))
    return {"key": key, **_key_to_api(row)}


@router.post("/{key_id}/revoke")
async def revoke_key(key_id: int, tenant: str = Depends(scoped_tenant)) -> dict[str, Any]:
    """Soft delete: the row stays for the audit trail, and the key stops working at once
    (tenant_from_api_key only accepts keys with revoked_at IS NULL)."""
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            """UPDATE api_keys SET revoked_at = coalesce(revoked_at, now())
               WHERE id = $1 AND tenant = $2
               RETURNING id, name, key_prefix, created_at, revoked_at""", key_id, tenant)
    if row is None:
        # Same answer for "no such key" and "another tenant's key".
        raise HTTPException(404, "key not found")
    return _key_to_api(row)
