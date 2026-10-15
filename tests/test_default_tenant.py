"""An admin can choose which tenant opens after signing in; a viewer can't change theirs.

Against the real Postgres (skipped if it isn't running), with throwaway users.
"""
import asyncio
import uuid

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.auth import decode_token, hash_password
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


@pytest.fixture
def env():
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")
    sfx = uuid.uuid4().hex[:8]
    admin, viewer = f"dt_admin_{sfx}", f"dt_viewer_{sfx}"
    home, other = f"dt_home_{sfx}", f"dt_other_{sfx}"

    async def setup(c):
        await c.execute("DELETE FROM login_failures WHERE ip = 'testclient'")
        for name, role, tenant in ((admin, "admin", home), (viewer, "viewer", other)):
            await c.execute("INSERT INTO users (username, password_hash, role, tenant) VALUES ($1, $2, $3, $4)",
                            name, hash_password(PASSWORD), role, tenant)
    _db(setup)
    with TestClient(app) as client:
        yield client, admin, viewer, home, other

    async def cleanup(c):
        await c.execute("DELETE FROM users WHERE username = ANY($1)", [admin, viewer])
        await c.execute("DELETE FROM login_failures WHERE ip = 'testclient'")
    _db(cleanup)


def login(client, user):
    r = client.post("/api/auth/login", json={"username": user, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()


def auth(session):
    return {"Authorization": f"Bearer {session['access_token']}"}


def test_admin_default_applies_now_and_at_next_sign_in(env):
    client, admin, _, home, other = env
    first = login(client, admin)
    assert first["user"]["tenant"] == home  # nothing chosen yet: their own tenant

    r = client.put("/api/auth/default-tenant", json={"tenant": other}, headers=auth(first))
    assert r.status_code == 200, r.text
    # The fresh token already carries the new default, so no new sign-in is needed.
    assert decode_token(r.json()["access_token"]).tenant == other
    assert login(client, admin)["user"]["tenant"] == other


def test_unknown_tenant_is_refused(env):
    client, admin, *_ = env
    r = client.put("/api/auth/default-tenant", json={"tenant": "no_such_tenant_x"}, headers=auth(login(client, admin)))
    assert r.status_code == 404
    assert login(client, admin)["user"]["tenant"] != "no_such_tenant_x"


def test_viewer_cannot_change_their_tenant(env):
    client, _, viewer, home, other = env
    session = login(client, viewer)
    r = client.put("/api/auth/default-tenant", json={"tenant": home}, headers=auth(session))
    assert r.status_code == 403
    # Even a value written straight into the database is ignored for a viewer.
    _db(lambda c: c.execute("UPDATE users SET default_tenant = $1 WHERE username = $2", home, viewer))
    assert login(client, viewer)["user"]["tenant"] == other
