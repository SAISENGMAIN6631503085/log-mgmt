"""The admin "API keys" page endpoints, end to end against Postgres (skipped if it isn't running)."""
import asyncio
import uuid
from datetime import datetime, timezone

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.auth import Claims, create_token
from app.config import settings
from app.main import app
from conftest import delete_events


def _db(fn):
    async def run():
        conn = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            return await fn(conn)
        finally:
            await conn.close()
    return asyncio.run(run())


def _auth(role: str, tenant: str) -> dict:
    return {"Authorization": f"Bearer {create_token(Claims(sub='x', role=role, tenant=tenant))}"}


@pytest.fixture
def env():
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")
    a, b = f"t_{uuid.uuid4().hex[:8]}", f"t_{uuid.uuid4().hex[:8]}"
    with TestClient(app) as client:
        yield client, a, b

    async def cleanup(c):
        await c.execute("DELETE FROM api_keys WHERE tenant = ANY($1)", [a, b])
        await c.execute("DELETE FROM alerts WHERE tenant = ANY($1)", [a, b])
    _db(cleanup)
    delete_events([a, b])


def _send(client, key: str) -> int:
    event = {"timestamp": datetime.now(timezone.utc).isoformat(), "event_type": "test"}
    return client.post("/api/ingest", json=event, headers={"X-API-Key": key}).status_code


def test_created_key_works_and_is_shown_once(env):
    client, a, _ = env
    r = client.post("/api/keys", json={"name": "shop website"}, headers=_auth("admin", a))
    assert r.status_code == 200
    created = r.json()
    assert created["key"].startswith("lm_") and created["prefix"] == created["key"][:8]
    assert _send(client, created["key"]) == 200
    # The list never contains the full key or its hash.
    listed = client.get("/api/keys", headers=_auth("admin", a)).json()["keys"]
    assert [k["name"] for k in listed] == ["shop website"]
    assert "key" not in listed[0] and "key_hash" not in listed[0]


def test_revoked_key_stops_working(env):
    client, a, _ = env
    created = client.post("/api/keys", json={"name": "fw"}, headers=_auth("admin", a)).json()
    r = client.post(f"/api/keys/{created['id']}/revoke", headers=_auth("admin", a))
    assert r.status_code == 200 and r.json()["revoked_at"]
    assert _send(client, created["key"]) == 401


def test_admin_manages_the_viewed_tenant_only(env):
    client, a, b = env
    created = client.post("/api/keys", params={"tenant": b}, json={"name": "b-key"}, headers=_auth("admin", a)).json()
    assert client.get("/api/keys", headers=_auth("admin", a)).json()["keys"] == []
    assert [k["name"] for k in client.get("/api/keys", params={"tenant": b}, headers=_auth("admin", a)).json()["keys"]] == ["b-key"]
    # Revoking b's key while viewing a: not found, and the key keeps working.
    assert client.post(f"/api/keys/{created['id']}/revoke", headers=_auth("admin", a)).status_code == 404
    assert _send(client, created["key"]) == 200


def test_viewers_cannot_manage_keys(env):
    client, a, _ = env
    h = _auth("viewer", a)
    assert client.get("/api/keys", headers=h).status_code == 403
    assert client.post("/api/keys", json={"name": "x"}, headers=h).status_code == 403


def test_blank_name_is_rejected(env):
    client, a, _ = env
    assert client.post("/api/keys", json={"name": "   "}, headers=_auth("admin", a)).status_code == 422
