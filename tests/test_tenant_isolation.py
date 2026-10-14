"""End-to-end tenant isolation through the real API and database (skipped if Postgres is down).

This is the security property reviewers will try to break, so it is tested over HTTP,
exactly as a client would call it.
"""
import asyncio
import uuid
from datetime import datetime, timezone

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.config import settings
from app.main import app
from app.normalizers.common import Event
from conftest import delete_events, store_events

PASSWORD = "test-password-1"


def _db(coro_fn):
    async def run():
        conn = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            return await coro_fn(conn)
        finally:
            await conn.close()
    return asyncio.run(run())


@pytest.fixture
def world():
    """Two random tenants, each with 3 events and a viewer, plus an admin."""
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")

    sfx = uuid.uuid4().hex[:8]
    ta, tb = f"ta_{sfx}", f"tb_{sfx}"
    users = {"viewerA": (f"va_{sfx}", "viewer", ta), "viewerB": (f"vb_{sfx}", "viewer", tb),
             "admin": (f"ad_{sfx}", "admin", ta)}
    pw_hash = hash_password(PASSWORD)

    async def setup(c):
        for name, role, tenant in users.values():
            await c.execute("INSERT INTO users (username, password_hash, role, tenant) VALUES ($1,$2,$3,$4)",
                            name, pw_hash, role, tenant)
    _db(setup)
    # Events go through the app's write path so they land in every event store (ClickHouse too).
    store_events([Event(ts=datetime.now(timezone.utc), tenant=tenant, source="api", event_type=f"e{i}",
                        raw={"tenant": tenant, "i": i})
                  for tenant in (ta, tb) for i in range(3)])

    with TestClient(app) as client:
        def login(who):
            r = client.post("/api/auth/login", json={"username": users[who][0], "password": PASSWORD})
            assert r.status_code == 200, r.text
            return {"Authorization": f"Bearer {r.json()['access_token']}"}
        yield client, login, ta, tb

    async def cleanup(c):
        await c.execute("DELETE FROM users WHERE username = ANY($1)", [u[0] for u in users.values()])
        # Failed sign-ins made by these tests (TestClient's address is "testclient"), so repeated
        # test runs never add up to a lockout of the real admin account.
        await c.execute("DELETE FROM login_failures WHERE ip = 'testclient'")
    _db(cleanup)
    delete_events([ta, tb])


def tenants_in(resp) -> set[str]:
    return {e["tenant"] for e in resp.json()["events"]}


def test_viewer_sees_only_own_tenant(world):
    client, login, ta, tb = world
    r = client.get("/api/events?limit=500", headers=login("viewerA"))
    assert r.status_code == 200
    assert tenants_in(r) == {ta} and len(r.json()["events"]) == 3


def test_each_viewer_isolated(world):
    client, login, ta, tb = world
    assert tenants_in(client.get("/api/events?limit=500", headers=login("viewerB"))) == {tb}


def test_viewer_requesting_other_tenant_is_403(world):
    client, login, ta, tb = world
    r = client.get(f"/api/events?tenant={tb}", headers=login("viewerA"))
    assert r.status_code == 403


def test_viewer_tenant_header_is_ignored(world):
    # Only ?tenant= is an input, and only for admins; any other header must not change scope.
    client, login, ta, tb = world
    headers = login("viewerA") | {"X-Tenant": tb, "Tenant": tb}
    assert tenants_in(client.get("/api/events?limit=500", headers=headers)) == {ta}


def test_admin_defaults_to_own_and_can_switch(world):
    client, login, ta, tb = world
    h = login("admin")
    assert tenants_in(client.get("/api/events?limit=500", headers=h)) == {ta}
    assert tenants_in(client.get(f"/api/events?tenant={tb}&limit=500", headers=h)) == {tb}


def test_no_token_is_401(world):
    client, *_ = world
    assert client.get("/api/events").status_code == 401


def test_garbage_token_is_401(world):
    client, *_ = world
    assert client.get("/api/events", headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401


def test_login_errors_are_identical(world):
    client, login, *_ = world
    wrong_pw = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    no_user = client.post("/api/auth/login", json={"username": f"ghost_{uuid.uuid4().hex}", "password": "nope"})
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()


def test_me_returns_claims(world):
    client, login, ta, _ = world
    body = client.get("/api/auth/me", headers=login("viewerA")).json()
    assert body["role"] == "viewer" and body["tenant"] == ta
