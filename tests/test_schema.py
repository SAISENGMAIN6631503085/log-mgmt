"""Integration tests for the migrations and partitioning. They need the compose Postgres
(`make up` first) and are skipped when it isn't reachable, so `make test` still works offline."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest

from app.config import settings
from app.migrate import ensure_partitions, run_migrations


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


async def _insert(conn, ts, source="firewall", tenant="t-test"):
    return await conn.fetchval(
        "INSERT INTO events (ts, tenant, source, raw) VALUES ($1, $2, $3, $4) RETURNING tableoid::regclass::text",
        ts, tenant, source, json.dumps({"msg": "x"}),
    )


def test_migrations_are_idempotent():
    async def body(conn):
        await run_migrations(conn)
        assert await run_migrations(conn) == []
        tables = {r["tablename"] for r in await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname='public'")}
        assert {"events", "users", "api_keys", "alerts", "schema_migrations"} <= tables
    run(body)


def test_event_lands_in_its_day_partition():
    async def body(conn):
        now = datetime.now(timezone.utc)
        assert await _insert(conn, now) == f"events_{now:%Y%m%d}"
    run(body)


def test_partition_boundaries_are_utc_days():
    async def body(conn):
        midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        assert await _insert(conn, midnight) == f"events_{midnight:%Y%m%d}"
        before = midnight - timedelta(microseconds=1)
        assert await _insert(conn, before) == f"events_{before:%Y%m%d}"
    run(body)


def test_partitions_cover_retention_window_and_week_ahead():
    async def body(conn):
        await ensure_partitions(conn, retention_days=7)
        today = datetime.now(timezone.utc).date()
        names = {r["c"] for r in await conn.fetch(
            "SELECT inhrelid::regclass::text AS c FROM pg_inherits WHERE inhparent = 'events'::regclass")}
        for offset in (-7, 0, 7):
            assert f"events_{today + timedelta(days=offset):%Y%m%d}" in names
    run(body)


def test_event_without_partition_is_rejected():
    # No DEFAULT partition by design: an out-of-range timestamp must fail loudly, not vanish.
    async def body(conn):
        with pytest.raises(asyncpg.PostgresError, match="no partition"):
            await _insert(conn, datetime(2000, 1, 1, tzinfo=timezone.utc))
    run(body)


def test_ensure_event_partition_creates_backdated_day():
    async def body(conn):
        day = datetime(2001, 2, 3, 12, tzinfo=timezone.utc)
        await conn.execute("SELECT ensure_event_partition($1)", day.date())
        await conn.execute("SELECT ensure_event_partition($1)", day.date())  # idempotent
        assert await _insert(conn, day) == "events_20010203"
    run(body)


def test_unknown_source_is_rejected():
    async def body(conn):
        with pytest.raises(asyncpg.CheckViolationError):
            await _insert(conn, datetime.now(timezone.utc), source="mainframe")
    run(body)
