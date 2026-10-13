"""Search over HTTP against the real database (skipped if Postgres is down)."""
import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.auth import Claims, create_token
from app.config import settings
from app.main import app

NOW = datetime.now(timezone.utc).replace(microsecond=0)

# (minutes ago, source, action, severity, src_ip, user, host, event_type, tags, raw)
ROWS = [
    (1,  "ad",       "login", 5, "203.0.113.50", "Administrator", "DC01", "logon_failure", ["auth_failure"], {"EventID": 4625}),
    (2,  "ad",       "login", 5, "203.0.113.50", "administrator", "DC01", "logon_failure", ["auth_failure"], {"EventID": 4625}),
    (3,  "firewall", "deny",  5, "198.51.100.9", None,            "fw01", "traffic",       ["blocked"],      {"message": "deny ssh"}),
    (4,  "aws",      "create", 2, "10.1.2.3",    "dave",          None,   "RunInstances",  [],               {"note": "100% done"}),
    (5,  "crowdstrike", "quarantine", 10, "10.0.1.42", "bob",     "WS-042", "detection",   ["edr_detection"], {"FileName": "mimikatz.exe"}),
    (60 * 30, "api", "login", 2, "198.51.100.7", "alice",         None,   "login_success", [],               {}),  # 30h ago
]


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
    tenant, other = f"s_{uuid.uuid4().hex[:8]}", f"o_{uuid.uuid4().hex[:8]}"

    async def setup(c):
        for mins, src, act, sev, ip, user, host, et, tags, raw in ROWS:
            await c.execute(
                """INSERT INTO events (ts, tenant, source, action, severity, src_ip, username, host, event_type, _tags, raw)
                   VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8,$9,$10,$11)""",
                NOW - timedelta(minutes=mins), tenant, src, act, sev, ip, user, host, et, tags, json.dumps(raw))
        # Same IP and user in another tenant: must never show up.
        await c.execute("INSERT INTO events (ts, tenant, source, src_ip, username, raw) VALUES ($1,$2,'ad','203.0.113.50','administrator','{}')",
                        NOW - timedelta(minutes=1), other)
        return await c.fetchval("SELECT id FROM events WHERE tenant = $1", other)
    other_id = _db(setup)

    token = create_token(Claims(sub="t", role="viewer", tenant=tenant))
    with TestClient(app) as client:
        def search(**params):
            r = client.get("/api/events", params=params, headers={"Authorization": f"Bearer {token}"})
            return r
        yield search, client, token, other_id
    _db(lambda c: c.execute("DELETE FROM events WHERE tenant = ANY($1)", [tenant, other]))
    _db(lambda c: c.execute("DELETE FROM alerts WHERE tenant = ANY($1)", [tenant, other]))


def ids(r):
    assert r.status_code == 200, r.text
    return [e["event_type"] for e in r.json()["events"]]


def test_default_window_is_last_24h_newest_first(env):
    search, *_ = env
    assert ids(search()) == ["logon_failure", "logon_failure", "traffic", "RunInstances", "detection"]


def test_explicit_time_range(env):
    search, *_ = env
    assert ids(search(**{"from": (NOW - timedelta(hours=31)).isoformat()})).count("login_success") == 1


@pytest.mark.parametrize("params,expected", [
    ({"source": ["aws", "crowdstrike"]}, ["RunInstances", "detection"]),
    ({"action": "deny"}, ["traffic"]),
    ({"severity_min": 6}, ["detection"]),
    ({"src_ip": "203.0.113.50"}, ["logon_failure", "logon_failure"]),
    ({"src_ip": "10.0.0.0/8"}, ["RunInstances", "detection"]),
    ({"user": "ADMINISTRATOR"}, ["logon_failure", "logon_failure"]),
    ({"host": "fw01"}, ["traffic"]),
    ({"event_type": "RunInstances"}, ["RunInstances"]),
    ({"tag": "auth_failure"}, ["logon_failure", "logon_failure"]),
    ({"q": "MIMIKATZ"}, ["detection"]),        # matches inside raw, any case
    ({"q": "100%"}, ["RunInstances"]),         # % is literal
    ({"q": "100_"}, []),                        # _ is literal too
    ({"source": "ad", "user": "bob"}, []),      # filters combine with AND
])
def test_filters(env, params, expected):
    search, *_ = env
    assert ids(search(**params)) == expected


def test_paging_with_cursor_visits_every_row_once(env):
    search, *_ = env
    seen, cursor = [], None
    for _ in range(10):
        params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
        body = search(**params).json()
        seen += [e["id"] for e in body["events"]]
        cursor = body["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 5 and len(set(seen)) == 5


def test_last_page_has_no_cursor(env):
    search, *_ = env
    assert search(limit=500).json()["next_cursor"] is None


@pytest.mark.parametrize("params", [
    {"src_ip": "not-an-ip"}, {"source": "mainframe"}, {"severity_min": 11},
    {"cursor": "garbage"}, {"limit": 0}, {"limit": 501},
    {"from": "2026-10-12T10:00:00Z", "to": "2026-10-12T09:00:00Z"},
])
def test_bad_params_are_422(env, params):
    search, *_ = env
    assert search(**params).status_code == 422


def test_response_uses_common_schema_names(env):
    search, *_ = env
    e = search(source="aws").json()["events"][0]
    assert "@timestamp" in e and e["user"] == "dave" and "username" not in e and e["src_ip"] == "10.1.2.3"


def test_get_single_event(env):
    search, client, token, _ = env
    event_id = search(source="aws").json()["events"][0]["id"]
    r = client.get(f"/api/events/{event_id}", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json()["event_type"] == "RunInstances"


def test_other_tenants_event_by_id_is_404(env):
    _, client, token, other_id = env
    r = client.get(f"/api/events/{other_id}", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404
