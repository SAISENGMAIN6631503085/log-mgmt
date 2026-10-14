import asyncio
import json
import logging

import asyncpg

from .ch_schema import ensure_schema
from .clickhouse import ch
from .config import settings
from .migrate import run_migrations

log = logging.getLogger("db")

# One pool per process, created at startup. A pool avoids paying connection setup per request.
pool: asyncpg.Pool | None = None


async def connect() -> None:
    global pool
    pool = await asyncpg.create_pool(
        settings.database_dsn, min_size=1, max_size=10, init=_init_connection
    )
    # Schema is brought up to date before the app accepts requests.
    async with pool.acquire() as conn:
        applied = await run_migrations(conn)
        if applied:
            print(f"migrations applied: {', '.join(applied)}")
    await ch.connect()
    await ensure_schema()  # ClickHouse events table, per-minute totals and TTL


async def _init_connection(conn: asyncpg.Connection) -> None:
    # Let asyncpg take/return Python dicts for jsonb columns instead of JSON strings.
    # Binary format: jsonb's binary form is a version byte (1) followed by the JSON text.
    await conn.set_type_codec(
        "jsonb",
        encoder=lambda v: b"\x01" + json.dumps(v).encode(),
        decoder=lambda b: json.loads(b[1:]),
        schema="pg_catalog",
        format="binary",
    )


async def disconnect(timeout: float = 10) -> None:
    """Close the pools. pool.close() waits until every connection is handed back; one left stuck
    (e.g. a background job cancelled in the middle of a query) would make shutdown wait forever,
    which hung CI test runs and would hang `docker stop`. So wait a while, then force-close."""
    if pool is not None:
        try:
            await asyncio.wait_for(pool.close(), timeout)
        except asyncio.TimeoutError:
            log.warning("database pool didn't close within %ss; closing it forcibly", timeout)
            pool.terminate()
    await ch.close()


async def ping() -> bool:
    """True if the database answers a trivial query."""
    if pool is None:
        return False
    try:
        async with pool.acquire() as conn:
            return await conn.fetchval("SELECT 1") == 1
    except (OSError, asyncpg.PostgresError):
        return False
