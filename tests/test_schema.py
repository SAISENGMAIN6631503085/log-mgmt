"""Integration tests for the Postgres migrations and the ClickHouse events table's day partitions.
They need the compose databases (`make up` first) and are skipped when they aren't reachable."""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest

from app.clickhouse import ch
from app.config import settings
from app.migrate import run_migrations
from conftest import _CH_CLEANUP, Event, store_events


async def _connect():
    try:
        return await asyncpg.connect(settings.database_dsn, timeout=2)
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")


def run(coro_fn):
    """Each test gets a fresh connection inside a transaction that is rolled back,
    so tests never leave rows behind in the dev database."""
    async def wrapper():
        conn = await _connect()
        tx = conn.transaction()
        await tx.start()
        try:
            await coro_fn(conn)
        finally:
            await tx.rollback()
            await conn.close()
    asyncio.run(wrapper())


def test_migrations_are_idempotent():
    async def body(conn):
        await run_migrations(conn)
        assert await run_migrations(conn) == []
        tables = {r["tablename"] for r in await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname='public'")}
        assert {"users", "api_keys", "alerts", "rule_settings", "login_failures", "schema_migrations"} <= tables
        assert "events" not in tables  # events live in ClickHouse (migration 007)
    run(body)


# --- ClickHouse day partitions ---------------------------------------------------

@pytest.fixture
def tenant():
    async def ping():
        try:
            return await ch.ping()
        finally:
            await ch.close()
    if not asyncio.run(ping()):
        pytest.skip("ClickHouse not reachable; run `make up` first")
    t = f"sc_{uuid.uuid4().hex[:8]}"
    yield t
    _CH_CLEANUP.add(t)


def _partition_of(tenant: str, ts: datetime) -> str:
    """Store one event at `ts`, return the id of the day partition it landed in."""
    store_events([Event(ts=ts, tenant=tenant, source="firewall", raw={"at": ts.isoformat()})])

    async def body():
        try:
            rows = await ch.query("SELECT _partition_id AS p FROM events WHERE tenant = {t:String} "
                                  "AND ts = {ts:DateTime64(3, 'UTC')}", {"t": tenant, "ts": ts})
            return rows[0]["p"]
        finally:
            await ch.close()
    return asyncio.run(body())


def test_event_lands_in_its_day_partition(tenant):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    assert _partition_of(tenant, now) == f"{now:%Y%m%d}"


def test_partition_boundaries_are_utc_days(tenant):
    midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    assert _partition_of(tenant, midnight) == f"{midnight:%Y%m%d}"
    before = midnight - timedelta(milliseconds=1)  # ClickHouse keeps milliseconds
    assert _partition_of(tenant, before) == f"{before:%Y%m%d}"

