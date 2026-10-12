"""Per-tenant ingest API keys (X-API-Key header)."""
import hashlib
import secrets

from fastapi import Header, HTTPException

from . import db

KEY_PREFIX = "lm_"  # makes leaked keys easy to recognise (and grep for) in code/logs


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


async def create_key(conn, tenant: str, name: str, key: str | None = None) -> str:
    """Store a key (hashed) and return the plaintext, which is only ever shown once."""
    key = key or generate_key()
    await conn.execute(
        """INSERT INTO api_keys (tenant, name, key_hash, key_prefix) VALUES ($1, $2, $3, $4)
           ON CONFLICT (key_hash) DO NOTHING""",
        tenant, name, hash_key(key), key[:8],
    )
    return key


async def tenant_from_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """FastAPI dependency: the tenant is decided by the key, never by the request body."""
    if not x_api_key:
        raise HTTPException(401, "missing X-API-Key header")
    async with db.pool.acquire() as conn:
        tenant = await conn.fetchval(
            "SELECT tenant FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL", hash_key(x_api_key)
        )
    if tenant is None:
        # Same message for unknown and revoked keys: don't tell an attacker which one it was.
        raise HTTPException(401, "invalid API key")
    return tenant
