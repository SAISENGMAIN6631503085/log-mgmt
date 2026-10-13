"""Duplicate protection (migration 003): the same event is stored once per tenant.
Runs against the real Postgres; skipped if it isn't running."""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.api_keys import create_key
from app.config import settings
from app.main import app


def _db(fn):
    async def run():
        c = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            return await fn(c)
        finally:
            await c.close()
    return asyncio.run(run())


@pytest.fixture
def env():
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")
    ta, tb = f"d_{uuid.uuid4().hex[:8]}", f"d_{uuid.uuid4().hex[:8]}"
    ka, kb = _db(lambda c: create_key(c, ta, "t")), _db(lambda c: create_key(c, tb, "t"))
    with TestClient(app) as client:
        yield client, ta, ka, tb, kb
    _db(lambda c: c.execute("DELETE FROM events WHERE tenant = ANY($1)", [ta, tb]))
    _db(lambda c: c.execute("DELETE FROM api_keys WHERE tenant = ANY($1)", [ta, tb]))
    _db(lambda c: c.execute("DELETE FROM alerts WHERE tenant = ANY($1)", [ta, tb]))


def count(tenant):
    return _db(lambda c: c.fetchval("SELECT count(*) FROM events WHERE tenant = $1", tenant))


def ts(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def post(client, key, body, source="api"):
    r = client.post(f"/api/ingest?source={source}", json=body, headers={"X-API-Key": key})
    assert r.status_code == 200, r.text
    return r.json()


def test_same_batch_twice_is_stored_once(env):
    client, ta, ka, *_ = env
    batch = [{"timestamp": ts(1), "event_type": "a"}, {"timestamp": ts(2), "event_type": "b"}]
    assert post(client, ka, batch) | {"rejected": []} == {"accepted": 2, "time_adjusted": 0, "duplicates": 0, "rejected_count": 0, "rejected": []}
    second = post(client, ka, batch)
    assert (second["accepted"], second["duplicates"]) == (0, 2)
    assert count(ta) == 2


def test_duplicates_inside_one_batch(env):
    client, ta, ka, *_ = env
    e = {"timestamp": ts(), "event_type": "a"}
    body = post(client, ka, [e, e, e])
    assert (body["accepted"], body["duplicates"]) == (1, 2) and count(ta) == 1


def test_key_order_and_whitespace_do_not_matter(env):
    # jsonb normalizes the payload, so these are the same event.
    client, ta, ka, *_ = env
    t = ts()
    post(client, ka, {"timestamp": t, "event_type": "a", "user": "x"})
    assert post(client, ka, {"user": "x", "event_type": "a", "timestamp": t})["duplicates"] == 1


def test_same_event_in_two_tenants_is_kept_in_both(env):
    client, ta, ka, tb, kb = env
    e = {"timestamp": ts(), "event_type": "a"}
    post(client, ka, e)
    assert post(client, kb, e)["accepted"] == 1
    assert count(ta) == count(tb) == 1


def test_different_content_is_not_a_duplicate(env):
    client, ta, ka, *_ = env
    t = ts()
    post(client, ka, {"timestamp": t, "event_type": "login_failed", "user": "alice"})
    assert post(client, ka, {"timestamp": t, "event_type": "login_failed", "user": "bob"})["accepted"] == 1


def test_events_without_timestamp_are_never_deduplicated(env):
    # They get the receipt time, so two sends are two different moments: keep both rather
    # than risk dropping real repeated events.
    client, ta, ka, *_ = env
    post(client, ka, {"event_type": "ping"})
    post(client, ka, {"event_type": "ping"})
    assert count(ta) == 2


def test_file_reupload(env):
    client, ta, ka, *_ = env
    t = ts()
    csv_body = f"TimeCreated,EventID,Computer,IpAddress\n{t},4625,DC01,203.0.113.5\n{t},4624,DC01,10.0.0.1\n"
    up = lambda: client.post("/api/ingest/file", headers={"X-API-Key": ka}, data={"source": "ad"},  # noqa: E731
                             files={"file": ("sec.csv", csv_body, "text/csv")}).json()
    assert up()["accepted"] == 2
    assert (r := up())["accepted"] == 0 and r["duplicates"] == 2
    assert count(ta) == 2


def test_syslog_retry_is_stored_once(env, monkeypatch):
    # Vector retries a batch when the backend didn't answer in time; that must not duplicate.
    client, *_ = env
    tenant = f"d_{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(settings, "syslog_ingest_token", "secret")
    monkeypatch.setattr(settings, "default_tenant", tenant)
    line = f"<132>{datetime.now(timezone.utc):%b %d %H:%M:%S} fw01 action=deny src=203.0.113.4 dst=10.0.0.1"
    for _ in range(2):
        client.post("/api/ingest/syslog", json=[{"message": line, "host": "192.0.2.1"}], headers={"X-Ingest-Token": "secret"})
    try:
        assert count(tenant) == 1
    finally:
        _db(lambda c: c.execute("DELETE FROM events WHERE tenant = $1", tenant))


def test_fingerprint_cannot_be_supplied_by_caller():
    # The trigger always overwrites it, so a forged value can't dodge (or cause) deduplication.
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable")

    async def body(c):
        async with c.transaction():
            fp = await c.fetchval(
                """INSERT INTO events (ts, tenant, source, raw, fingerprint)
                   VALUES (now(), 'fp_test', 'api', '{"a":1}', '\\x00') RETURNING fingerprint""")
            expected = await c.fetchval(
                """SELECT sha256(convert_to(jsonb_build_array('fp_test'::text, 'api'::text, '{"a":1}'::jsonb)::text, 'UTF8'))""")
            assert fp == expected
            raise asyncpg.exceptions.RaiseError("rollback")  # undo the insert
    with pytest.raises(asyncpg.exceptions.RaiseError):
        _db(body)
