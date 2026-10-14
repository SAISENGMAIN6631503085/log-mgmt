"""The ClickHouse event store: copy on ingest, duplicate skipping, safe parameters.

Integration tests need the compose ClickHouse (skipped if it isn't reachable); the unit tests don't.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import ch_events
from app.api_keys import create_key
from app.clickhouse import _param, ch
from app.config import settings
from app.main import app
from app.normalizers.common import Event
from conftest import _CH_CLEANUP

# --- unit -------------------------------------------------------------------------------


def _event(tenant="t", raw=None) -> Event:
    return Event(ts=datetime.now(timezone.utc), tenant=tenant, source="api", raw=raw or {"a": 1, "b": 2})


def test_fingerprint_ignores_key_order():
    assert ch_events.fingerprint(_event(raw={"a": 1, "b": 2})) == ch_events.fingerprint(_event(raw={"b": 2, "a": 1}))
    assert ch_events.fingerprint(_event(raw={"a": 1})) != ch_events.fingerprint(_event(raw={"a": 2}))
    assert ch_events.fingerprint(_event(tenant="x")) != ch_events.fingerprint(_event(tenant="y"))


def test_ids_are_unique_increasing_and_safe_in_javascript():
    ids = [ch_events.new_id() for _ in range(20_000)]  # more than fit in one millisecond
    assert len(set(ids)) == len(ids)
    assert ids == sorted(ids)
    assert max(ids) < 2 ** 53  # JSON numbers in browsers are exact only up to 2^53


def test_parameters_are_quoted_not_pasted():
    # A hostile value stays inside one quoted array element.
    assert _param(["a'b", "c\\d"]) == "['a\\'b','c\\\\d']"
    assert _param(datetime(2026, 10, 14, 1, 2, 3, 456000, tzinfo=timezone.utc)) == "2026-10-14 01:02:03.456"


# --- integration ----------------------------------------------------------------------------


def _run(coro):
    async def go():
        await ch.connect()
        try:
            return await coro()
        finally:
            await ch.close()
    return asyncio.run(go())


@pytest.fixture
def tenant():
    if not settings.clickhouse_url:
        pytest.skip("ClickHouse not configured")
    try:
        _run(lambda: ch.query("SELECT 1 AS ok"))
    except Exception:  # noqa: BLE001
        pytest.skip("ClickHouse not reachable; run `make up` first")
    t = f"chs_{uuid.uuid4().hex[:8]}"
    yield t
    _CH_CLEANUP.add(t)  # deleted once at the end of the run (see conftest.py)


def _count(t: str) -> int:
    [row] = _run(lambda: ch.query("SELECT count() AS n FROM events FINAL WHERE tenant = {t:String}", {"t": t}))
    return row["n"]


def test_new_events_are_stored_and_repeats_skipped(tenant):
    events = [_event(tenant, {"n": i}) for i in range(3)]
    assert _run(lambda: ch_events.insert_events(events)) == 3
    assert _run(lambda: ch_events.insert_events(events)) == 0  # same batch again
    assert _count(tenant) == 3


def test_big_batch_is_checked_in_chunks(tenant):
    # More events than one duplicate-check query takes: must not hit the URL length limit.
    events = [_event(tenant, {"n": i}) for i in range(ch_events.CHECK_CHUNK * 3 + 7)]
    assert _run(lambda: ch_events.insert_events(events)) == len(events)
    assert _run(lambda: ch_events.insert_events(events)) == 0
    assert _count(tenant) == len(events)


def test_repeats_inside_one_batch_count_once(tenant):
    e = _event(tenant, {"same": True})
    assert _run(lambda: ch_events.insert_events([e, e, e])) == 1
    assert _count(tenant) == 1


def test_same_content_at_another_time_is_a_new_event(tenant):
    # Same rule as Postgres' unique (fingerprint, ts).
    from datetime import timedelta
    a = _event(tenant, {"x": 1})
    b = a.model_copy(update={"ts": a.ts + timedelta(seconds=5)})
    assert _run(lambda: ch_events.insert_events([a, b])) == 2
    assert _run(lambda: ch_events.insert_events([a, b])) == 0
    assert _count(tenant) == 2


def test_ingest_copies_into_clickhouse(tenant):
    async def make_key():
        import asyncpg
        conn = await asyncpg.connect(settings.database_dsn)
        try:
            return await create_key(conn, tenant, "test")
        finally:
            await conn.close()
    key = asyncio.run(make_key())
    try:
        with TestClient(app) as client:
            body = [{"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "login_failed",
                     "ip": "203.0.113.9", "user": f"u{i}"} for i in range(4)]
            assert client.post("/api/ingest", json=body, headers={"X-API-Key": key}).json()["accepted"] == 4
        assert _count(tenant) == 4
    finally:
        async def cleanup():
            import asyncpg
            conn = await asyncpg.connect(settings.database_dsn)
            try:
                await conn.execute("DELETE FROM events WHERE tenant = $1", tenant)
                await conn.execute("DELETE FROM api_keys WHERE tenant = $1", tenant)
            finally:
                await conn.close()
        asyncio.run(cleanup())


def test_copied_events_keep_their_original_arrival_time(tenant):
    """The backfill passes Postgres' ingested_at; without it, old events look newly arrived."""
    # Recent times: rows older than RETENTION_DAYS can be dropped by the TTL during the test.
    now = datetime.now(timezone.utc).replace(microsecond=0)
    arrived = now - timedelta(hours=2)
    e = Event(ts=now - timedelta(hours=3), tenant=tenant, source="api", raw={"k": 1})
    assert _run(lambda: ch_events.insert_events([e], [arrived])) == 1
    [row] = _run(lambda: ch.query("SELECT toString(ingested_at) AS at FROM events WHERE tenant = {t:String}",
                                  {"t": tenant}))
    assert row["at"] == arrived.strftime("%Y-%m-%d %H:%M:%S.000")
