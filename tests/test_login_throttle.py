"""Sign-in throttling: too many failed sign-ins lock the account (or the address) for a while.

Against the real Postgres (skipped if it isn't running). TestClient's address is "testclient".
"""
import asyncio
import uuid
from datetime import timedelta

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
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
    names = [f"lt_{uuid.uuid4().hex[:8]}" for _ in range(2)]

    async def setup(c):
        await c.execute("DELETE FROM login_failures WHERE ip = 'testclient'")
        for n in names:
            await c.execute("INSERT INTO users (username, password_hash, role, tenant) VALUES ($1, $2, 'viewer', 't')",
                            n, hash_password(PASSWORD))
    _db(setup)
    with TestClient(app) as client:
        yield client, names

    async def cleanup(c):
        await c.execute("DELETE FROM users WHERE username = ANY($1)", names)
        await c.execute("DELETE FROM login_failures WHERE ip = 'testclient'")
    _db(cleanup)


def login(client, user, password):
    return client.post("/api/auth/login", json={"username": user, "password": password})


def test_fifth_failure_locks_the_account_even_for_the_right_password(env):
    client, (user, other) = env
    for _ in range(settings.login_max_failures):
        assert login(client, user, "wrong").status_code == 401
    r = login(client, user, PASSWORD)
    assert r.status_code == 429 and "Too many failed sign-ins" in r.json()["detail"]
    assert 0 < int(r.headers["Retry-After"]) <= settings.login_lock_minutes * 60
    # Only that account: another one on the same address still signs in.
    assert login(client, other, PASSWORD).status_code == 200


def test_success_resets_the_count(env):
    client, (user, _) = env
    for _ in range(settings.login_max_failures - 1):
        login(client, user, "wrong")
    assert login(client, user, PASSWORD).status_code == 200
    for _ in range(settings.login_max_failures - 1):
        assert login(client, user, "wrong").status_code == 401


def test_lock_ends_when_the_failures_leave_the_window(env):
    client, (user, _) = env
    for _ in range(settings.login_max_failures):
        login(client, user, "wrong")
    assert login(client, user, PASSWORD).status_code == 429
    _db(lambda c: c.execute("UPDATE login_failures SET ts = ts - $1::interval WHERE username = $2",
                            timedelta(minutes=settings.login_lock_minutes + 1), user))
    assert login(client, user, PASSWORD).status_code == 200


def test_unknown_usernames_lock_the_same_way(env):
    # Same 429 for an account that doesn't exist, so the lock can't be used to find real usernames.
    client, _ = env
    ghost = f"ghost_{uuid.uuid4().hex}"
    for _ in range(settings.login_max_failures):
        assert login(client, ghost, "wrong").status_code == 401
    assert login(client, ghost, "wrong").status_code == 429


def test_one_address_trying_many_accounts_is_paused(env, monkeypatch):
    client, (user, _) = env
    monkeypatch.setattr(settings, "login_ip_max_failures", 3)
    for i in range(3):
        assert login(client, f"guess_{i}_{uuid.uuid4().hex[:6]}", "wrong").status_code == 401
    assert login(client, user, PASSWORD).status_code == 429
