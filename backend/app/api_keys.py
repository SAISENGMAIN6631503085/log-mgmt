"""Per-tenant ingest API keys (X-API-Key header).

Keys are created, listed and revoked here (the admin "API keys" page and `make seed`); the Go
ingest service checks them when logs arrive, by looking up the same SHA-256 hash.
"""
import hashlib
import secrets

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
