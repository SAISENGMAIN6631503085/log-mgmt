"""Ingestion endpoints end to end against the real Postgres (skipped if it isn't running).

Each test uses a fresh random tenant and deletes its rows afterwards, so tests don't see
each other's data or leave anything in the dev database.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.api_keys import create_key
from app.config import settings
from app.main import app
from app.normalizers.syslog import parse_tenant_map
from app.routers import ingest


def _db(coro_fn):
    async def run():
        conn = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            return await coro_fn(conn)
        finally:
            await conn.close()
    return asyncio.run(run())


@pytest.fixture
def env():
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")

    tenant_a, tenant_b = f"t_{uuid.uuid4().hex[:8]}", f"t_{uuid.uuid4().hex[:8]}"
    key_a = _db(lambda c: create_key(c, tenant_a, "test"))
    key_b = _db(lambda c: create_key(c, tenant_b, "test"))
    with TestClient(app) as client:
        yield client, tenant_a, key_a, tenant_b, key_b

    async def cleanup(c):
        await c.execute("DELETE FROM events WHERE tenant = ANY($1)", [tenant_a, tenant_b])
        await c.execute("DELETE FROM api_keys WHERE tenant = ANY($1)", [tenant_a, tenant_b])
    _db(cleanup)


def count(tenant: str, **where) -> int:
    clause = "".join(f" AND {k} = ${i + 2}" for i, k in enumerate(where))
    return _db(lambda c: c.fetchval(f"SELECT count(*) FROM events WHERE tenant = $1{clause}", tenant, *where.values()))


def now_iso(**delta) -> str:
    return (datetime.now(timezone.utc) + timedelta(**delta)).isoformat()


def test_single_event(env):
    client, tenant, key, *_ = env
    r = client.post("/api/ingest", json={"timestamp": now_iso(), "event_type": "login_failed", "ip": "203.0.113.7"},
                    headers={"X-API-Key": key})
    assert r.status_code == 200 and r.json()["accepted"] == 1
    assert count(tenant, source="api") == 1


def test_tenant_comes_from_key_not_body(env):
    # Behaviour changed on purpose: a tenant in the body that differs from the key's tenant is
    # rejected (before, it was silently stored under the key's tenant). Nothing may land in tenant_b.
    client, tenant_a, key_a, tenant_b, _ = env
    body = client.post("/api/ingest", json={"timestamp": now_iso(), "tenant": tenant_b}, headers={"X-API-Key": key_a}).json()
    assert body["accepted"] == 0 and body["rejected_count"] == 1
    assert "use that tenant's key" in body["rejected"][0]["error"]
    assert count(tenant_a) == 0 and count(tenant_b) == 0


def test_matching_tenant_in_body_is_accepted(env):
    client, tenant_a, key_a, *_ = env
    r = client.post("/api/ingest", json={"timestamp": now_iso(), "tenant": tenant_a}, headers={"X-API-Key": key_a})
    assert r.json()["accepted"] == 1 and count(tenant_a) == 1


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "lm_wrong"}])
def test_missing_or_wrong_key_is_401(env, headers):
    client, tenant, *_ = env
    assert client.post("/api/ingest", json={"timestamp": now_iso()}, headers=headers).status_code == 401
    assert count(tenant) == 0


def test_revoked_key_is_401(env):
    client, tenant, key, *_ = env
    _db(lambda c: c.execute("UPDATE api_keys SET revoked_at = now() WHERE tenant = $1", tenant))
    assert client.post("/api/ingest", json={"timestamp": now_iso()}, headers={"X-API-Key": key}).status_code == 401


def test_batch_partial_success(env):
    client, tenant, key, *_ = env
    batch = [
        {"timestamp": now_iso(), "event_type": "ok"},
        {"timestamp": "not a date"},
        {"timestamp": now_iso(days=-30)},  # outside retention: stored at receipt time, tagged
        {"timestamp": now_iso(), "severity": 3},
    ]
    body = client.post("/api/ingest", json=batch, headers={"X-API-Key": key}).json()
    assert body["accepted"] == 3 and body["rejected_count"] == 1 and body["time_adjusted"] == 1
    assert [r["index"] for r in body["rejected"]] == [1]
    assert count(tenant) == 3


def test_other_json_source_via_query(env):
    client, tenant, key, *_ = env
    record = {"eventTime": now_iso(), "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
              "responseElements": {"ConsoleLogin": "Failure"}, "sourceIPAddress": "203.0.113.9"}
    # Two distinct records (identical ones would now be de-duplicated, see test_dedup.py).
    records = [record | {"userIdentity": {"userName": "carol"}}, record | {"userIdentity": {"userName": "dave"}}]
    r = client.post("/api/ingest?source=aws", json={"Records": records}, headers={"X-API-Key": key})
    assert r.json()["accepted"] == 2 and r.json()["duplicates"] == 0 and count(tenant, source="aws") == 2


def test_unknown_source_is_400(env):
    client, _, key, *_ = env
    assert client.post("/api/ingest?source=nope", json={}, headers={"X-API-Key": key}).status_code == 400


def test_too_many_events_is_413(env, monkeypatch):
    client, _, key, *_ = env
    monkeypatch.setattr(ingest, "MAX_EVENTS_PER_REQUEST", 2)
    r = client.post("/api/ingest", json=[{"timestamp": now_iso()}] * 3, headers={"X-API-Key": key})
    assert r.status_code == 413


def test_file_upload_csv(env):
    client, tenant, key, *_ = env
    t = now_iso()
    csv_body = f"TimeCreated,EventID,Computer,TargetUserName,IpAddress,IpPort\n{t},4625,DC01,bob,203.0.113.5,5000\n{t},4624,DC01,bob,-,-\n"
    r = client.post("/api/ingest/file", headers={"X-API-Key": key},
                    data={"source": "ad"}, files={"file": ("sec.csv", csv_body, "text/csv")})
    assert r.json()["accepted"] == 2 and count(tenant, source="ad") == 2


def test_file_upload_unparseable_is_400(env):
    client, _, key, *_ = env
    r = client.post("/api/ingest/file", headers={"X-API-Key": key},
                    data={"source": "aws"}, files={"file": ("x.json", "not json", "application/json")})
    assert r.status_code == 400


def test_file_upload_needs_key(env):
    client, *_ = env
    r = client.post("/api/ingest/file", data={"source": "ad"}, files={"file": ("x.csv", "a\n1\n", "text/csv")})
    assert r.status_code == 401


def _bearer(role: str, tenant: str) -> dict:
    from app.auth import Claims, create_token
    return {"Authorization": f"Bearer {create_token(Claims(sub='x', role=role, tenant=tenant))}"}


def _ad_csv() -> str:
    return f"TimeCreated,EventID,Computer,TargetUserName,IpAddress,IpPort\n{now_iso()},4625,DC01,bob,203.0.113.5,5000\n"


def test_ui_upload_goes_to_the_viewed_tenant(env):
    # The website's upload: admin's login token, tenant from ?tenant= (not an API key).
    client, tenant_a, _, tenant_b, _ = env
    r = client.post("/api/ingest/upload", params={"tenant": tenant_b}, headers=_bearer("admin", tenant_a),
                    data={"source": "ad"}, files={"file": ("sec.csv", _ad_csv(), "text/csv")})
    assert r.status_code == 200 and r.json()["accepted"] == 1
    assert count(tenant_b, source="ad") == 1 and count(tenant_a) == 0


def test_ui_upload_is_admin_only(env):
    client, tenant_a, *_ = env
    r = client.post("/api/ingest/upload", headers=_bearer("viewer", tenant_a),
                    data={"source": "ad"}, files={"file": ("sec.csv", _ad_csv(), "text/csv")})
    assert r.status_code == 403 and count(tenant_a) == 0


def test_ui_upload_needs_login(env):
    client, *_ = env
    r = client.post("/api/ingest/upload", data={"source": "ad"}, files={"file": ("sec.csv", _ad_csv(), "text/csv")})
    assert r.status_code == 401


def _syslog_line(text: str) -> str:
    return f"<132>{datetime.now(timezone.utc):%b %d %H:%M:%S} {text}"


def test_syslog_requires_token(env, monkeypatch):
    client, *_ = env
    monkeypatch.setattr(settings, "syslog_ingest_token", "secret")
    rec = [{"message": _syslog_line("fw action=deny src=1.2.3.4"), "host": "10.0.0.1"}]
    assert client.post("/api/ingest/syslog", json=rec).status_code == 401
    assert client.post("/api/ingest/syslog", json=rec, headers={"X-Ingest-Token": "wrong"}).status_code == 401


def test_syslog_refused_when_no_token_configured(env, monkeypatch):
    # Fail closed: an empty token in config must not mean "no auth".
    client, *_ = env
    monkeypatch.setattr(settings, "syslog_ingest_token", "")
    r = client.post("/api/ingest/syslog", json=[], headers={"X-Ingest-Token": ""})
    assert r.status_code == 401


def test_syslog_tenant_by_sender_and_classification(env, monkeypatch):
    client, tenant_a, _, tenant_b, _ = env
    monkeypatch.setattr(settings, "syslog_ingest_token", "secret")
    monkeypatch.setattr(ingest, "_TENANT_MAP", parse_tenant_map(f"10.1.0.0/16={tenant_a},10.2.0.0/16={tenant_b}"))
    recs = [
        {"message": _syslog_line("fw01 action=deny src=203.0.113.4 dst=10.1.0.5") + "\n", "host": "10.1.0.9"},
        {"message": _syslog_line("sw01 %LINK-3-UPDOWN: event_type=link_down"), "host": "10.2.3.4"},
    ]
    body = client.post("/api/ingest/syslog", json=recs, headers={"X-Ingest-Token": "secret"}).json()
    assert body["accepted"] == 2
    assert count(tenant_a, source="firewall") == 1
    assert count(tenant_b, source="network") == 1
