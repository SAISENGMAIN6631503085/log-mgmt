"""Admins can add a tenant and give its staff a viewer sign-in; that viewer only ever sees their
own tenant, and viewers can't use these endpoints.

Against the real Postgres (skipped if it isn't running), with throwaway tenants and users.
"""
import asyncio
import uuid

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.auth import Claims, create_token
from app.config import settings
from app.main import app

PASSWORD = "correct horse battery"


def _db(fn):
    async def run():
        conn = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            return await fn(conn)
        finally:
            await conn.close()
    return asyncio.run(run())


def bearer(role: str, tenant: str) -> dict:
    return {"Authorization": f"Bearer {create_token(Claims(sub='x', role=role, tenant=tenant))}"}


@pytest.fixture
def env():
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")
    sfx = uuid.uuid4().hex[:8]
    tenant, user = f"tn{sfx}", f"tv{sfx}"
    _db(lambda c: c.execute("DELETE FROM login_failures WHERE ip = 'testclient'"))
    with TestClient(app) as client:
        yield client, tenant, user

    async def cleanup(c):
        await c.execute("DELETE FROM users WHERE username = $1", user)
        await c.execute("DELETE FROM api_keys WHERE lower(tenant) = lower($1)", tenant)
        await c.execute("DELETE FROM login_failures WHERE ip = 'testclient'")
    _db(cleanup)


def test_onboard_a_customer_end_to_end(env):
    client, tenant, user = env
    admin = bearer("admin", "demoA")

    r = client.post("/api/admin/tenants", json={"name": tenant}, headers=admin)
    assert r.status_code == 201, r.text
    key = r.json()["key"]
    assert key.startswith("lm_")
    assert tenant in [t["tenant"] for t in client.get("/api/admin/tenants", headers=admin).json()]
    assert tenant in client.get("/api/tenants", headers=admin).json()  # shows in the tenant menu

    r = client.post(f"/api/admin/tenants/{tenant}/viewers", json={"username": user, "password": PASSWORD}, headers=admin)
    assert r.status_code == 201, r.text
    row = next(t for t in client.get("/api/admin/tenants", headers=admin).json() if t["tenant"] == tenant)
    assert row == {"tenant": tenant, "viewers": [user], "active_keys": 1}

    # The new viewer signs in, lands on their tenant, and is refused anything else.
    s = client.post("/api/auth/login", json={"username": user, "password": PASSWORD}).json()
    assert s["user"] == {"sub": user, "role": "viewer", "tenant": tenant}
    h = {"Authorization": f"Bearer {s['access_token']}"}
    assert client.get("/api/events", headers=h).status_code == 200
    assert client.get("/api/events", params={"tenant": "demoA"}, headers=h).status_code == 403


def test_duplicates_and_bad_names_are_refused(env):
    client, tenant, user = env
    admin = bearer("admin", "demoA")
    assert client.post("/api/admin/tenants", json={"name": tenant}, headers=admin).status_code == 201
    # Same name in other letter case: refused, so two tenants can't be mixed up.
    assert client.post("/api/admin/tenants", json={"name": tenant.upper()}, headers=admin).status_code == 409
    assert client.post("/api/admin/tenants", json={"name": "demoa"}, headers=admin).status_code == 409
    for bad in ["", "1abc", "has space", "a", "x" * 40, "../etc"]:
        assert client.post("/api/admin/tenants", json={"name": bad}, headers=admin).status_code == 422, bad

    url = f"/api/admin/tenants/{tenant}/viewers"
    assert client.post(url, json={"username": user, "password": "short"}, headers=admin).status_code == 422
    assert client.post(url, json={"username": "VIEWERA", "password": PASSWORD}, headers=admin).status_code == 409
    no_such = client.post("/api/admin/tenants/no_such_tenant_z/viewers", json={"username": user, "password": PASSWORD},
                          headers=admin)
    assert no_such.status_code == 404


def test_viewers_cannot_use_tenant_admin(env):
    client, tenant, user = env
    viewer = bearer("viewer", "demoA")
    assert client.get("/api/admin/tenants", headers=viewer).status_code == 403
    assert client.post("/api/admin/tenants", json={"name": tenant}, headers=viewer).status_code == 403
    assert client.post("/api/admin/tenants/demoA/viewers", json={"username": user, "password": PASSWORD},
                       headers=viewer).status_code == 403
    assert client.get("/api/admin/tenants").status_code == 401
