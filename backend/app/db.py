import asyncpg

from .config import settings

# One pool per process, created at startup. A pool avoids paying connection setup per request.
pool: asyncpg.Pool | None = None


async def connect() -> None:
    global pool
    pool = await asyncpg.create_pool(settings.database_dsn, min_size=1, max_size=10)


async def disconnect() -> None:
    if pool is not None:
        await pool.close()


async def ping() -> bool:
    """True if the database answers a trivial query."""
    if pool is None:
        return False
    try:
        async with pool.acquire() as conn:
            return await conn.fetchval("SELECT 1") == 1
    except (OSError, asyncpg.PostgresError):
        return False
