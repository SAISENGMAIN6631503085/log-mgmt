"""Dashboard stats endpoint (real Postgres; skipped if it isn't running)."""
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
from app.routers.stats import bucket_for


@pytest.mark.parametrize("span,bucket", [
    (timedelta(hours=1), timedelta(minutes=15)),
    (timedelta(hours=24), timedelta(hours=1)),
    (timedelta(days=7), timedelta(days=1)),
])
def test_bucket_for(span, bucket):
    assert bucket_for(span) == bucket


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
    t, other = f"st_{uuid.uuid4().hex[:8]}", f"st_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    rows = [  # minutes ago, source, severity, src_ip, tags
        (5, "ad", 5, "203.0.113.50", ["auth_failure"]),
        (6, "ad", 5, "203.0.113.50", ["auth_failure"]),
        (7, "firewall", 9, "198.51.100.9", []),
        (200, "aws", 2, None, []),
    ]

    async def setup(c):
        for i, (m, src, sev, ip, tags) in enumerate(rows):
            await c.execute("""INSERT INTO events (ts, tenant, source, severity, src_ip, event_type, _tags, raw)
                               VALUES ($1,$2,$3,$4,$5::inet,$6,$7,$8)""",
                            now - timedelta(minutes=m), t, src, sev, ip, f"type{i % 2}", tags, json.dumps({"i": i}))
        await c.execute("INSERT INTO events (ts, tenant, source, raw) VALUES ($1, $2, 'api', '{}')", now, other)
        await c.execute("""INSERT INTO alerts (tenant, rule_id, rule_name, severity, event_count, window_start, window_end)
                           VALUES ($1, 'r', 'r', 7, 5, $2, $2)""", t, now)
    _db(setup)
    with TestClient(app) as client:
        yield client, t, other
    _db(lambda c: c.execute("DELETE FROM events WHERE tenant = ANY($1)", [t, other]))
    _db(lambda c: c.execute("DELETE FROM alerts WHERE tenant = $1", t))


def get(client, as_tenant, role="viewer", **params):
    """Call /api/stats as a user of `as_tenant`; extra kwargs (e.g. tenant=) become query params."""
    h = {"Authorization": f"Bearer {create_token(Claims(sub='x', role=role, tenant=as_tenant))}"}
    return client.get("/api/stats", params=params, headers=h)


def test_totals_and_breakdowns(env):
    client, t, _ = env
    d = get(client, t).json()
    assert d["totals"] == {"events": 4, "auth_failures": 2, "high_severity": 1, "unique_src_ips": 2, "open_alerts": 1}
    assert {r["key"]: r["n"] for r in d["by_source"]} == {"ad": 2, "firewall": 1, "aws": 1}
    assert [r["key"] for r in d["by_severity"]] == ["critical", "high", "medium", "low", "unknown"]
    assert {r["key"]: r["n"] for r in d["by_severity"]} == {"critical": 1, "high": 0, "medium": 2, "low": 1, "unknown": 0}
    assert d["top_src_ips"][0] == {"key": "203.0.113.50", "n": 2, "auth_failures": 2}


def test_timeline_has_zero_buckets_and_sums_to_total(env):
    client, t, _ = env
    d = get(client, t).json()
    assert d["bucket_seconds"] == 3600
    assert len(d["timeline"]) >= 24
    assert sum(p["n"] for p in d["timeline"]) == 4
    assert any(p["n"] == 0 for p in d["timeline"])


def test_time_range_filters(env):
    client, t, _ = env
    d = get(client, t, **{"from": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()}).json()
    assert d["totals"]["events"] == 3 and d["bucket_seconds"] == 900


def test_stats_are_tenant_scoped(env):
    client, t, other = env
    assert get(client, other).json()["totals"]["events"] == 1
    assert get(client, t, tenant=other).status_code == 403


def test_tenants_list_is_admin_only(env):
    client, t, _ = env
    viewer = {"Authorization": f"Bearer {create_token(Claims(sub='x', role='viewer', tenant=t))}"}
    admin = {"Authorization": f"Bearer {create_token(Claims(sub='x', role='admin', tenant=t))}"}
    assert client.get("/api/tenants", headers=viewer).status_code == 403
    assert "demoA" in client.get("/api/tenants", headers=admin).json()
