"""Shutdown must finish even if a database connection is never handed back (it used to wait
forever, which hung CI runs). Needs the compose Postgres; skipped if it isn't running."""
import asyncio

import asyncpg
import pytest

from app import db


def test_disconnect_finishes_when_a_connection_is_stuck():
    async def body():
        try:
            await db.connect()
        except (OSError, asyncpg.PostgresError):
            pytest.skip("Postgres not reachable; run `make up` first")
        await db.pool.acquire()  # taken and never released, like a job cancelled mid-query
        # Without the timeout this would wait forever; give it 5 s to prove it doesn't.
        await asyncio.wait_for(db.disconnect(timeout=0.5), 5)
        assert db.pool._closed
    asyncio.run(body())

