"""Country enrichment. Uses a fake database, so results don't depend on DB-IP's monthly data."""
import asyncio
import uuid
from datetime import datetime, timezone

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app import geoip
from app.auth import Claims, create_token
from app.config import settings
from app.main import app
from conftest import Event, delete_events, store_events


class FakeReader:
    DATA = {"1.46.10.5": {"country": {"iso_code": "TH"}}, "185.107.80.9": {"country": {"iso_code": "NL"}}}

    def get(self, ip):
        if ip == "not-an-ip":
            raise ValueError(ip)
        return self.DATA.get(ip)


@pytest.fixture
def fake_db(monkeypatch):
    monkeypatch.setattr(geoip, "_reader", lambda: FakeReader())
    geoip.country.cache_clear()
    yield
    geoip.country.cache_clear()


def test_known_ips_get_their_country(fake_db):
    assert geoip.country("1.46.10.5") == "TH"
    assert geoip.country("185.107.80.9") == "NL"


def test_private_unknown_and_missing_ips_have_no_country(fake_db):
    assert geoip.country("10.0.1.10") is None
    assert geoip.country("203.0.113.7") is None  # documentation range, as in the assignment samples
    assert geoip.country(None) is None
    assert geoip.country("not-an-ip") is None


def test_missing_database_turns_enrichment_off(monkeypatch):
    monkeypatch.setattr(settings, "geoip_db", "/nonexistent/geo.mmdb")
    geoip._reader.cache_clear()
    geoip.country.cache_clear()
    try:
        assert geoip.enabled() is False
        assert geoip.country("1.46.10.5") is None
    finally:
        geoip._reader.cache_clear()
        geoip.country.cache_clear()


# --- stored country -> search -> stats ------------------------------------------------
# Adding the country at ingest is the Go service's job (ingest/server: TestCountryIsAddedAtIngest).
# Here: events stored with a country, as the service stores them, are searchable and counted.

def _db(fn):
    async def run():
        conn = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            return await fn(conn)
        finally:
            await conn.close()
    return asyncio.run(run())


@pytest.fixture
def env(fake_db):
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")
    tenant = f"geo_{uuid.uuid4().hex[:8]}"
    with TestClient(app) as client:
        yield client, tenant

    async def cleanup(c):
        await c.execute("DELETE FROM alerts WHERE tenant = $1", tenant)
    _db(cleanup)
    delete_events([tenant])


def test_country_is_stored_searchable_and_counted(env):
    client, tenant = env
    now = datetime.now(timezone.utc)
    store_events([
        Event(ts=now, tenant=tenant, source="api", event_type="login_failed", src_ip="1.46.10.5", src_country="TH",
              user="a", tags=["auth_failure"], raw={"u": "a"}),
        Event(ts=now, tenant=tenant, source="api", event_type="login_failed", src_ip="1.46.10.5", src_country="TH",
              user="b", tags=["auth_failure"], raw={"u": "b"}),
        Event(ts=now, tenant=tenant, source="api", event_type="login_success", src_ip="10.0.1.10", user="c", raw={"u": "c"}),
    ])

    auth = {"Authorization": f"Bearer {create_token(Claims(sub='x', role='viewer', tenant=tenant))}"}
    found = client.get("/api/events", params={"country": "th"}, headers=auth).json()["events"]
    assert {e["user"] for e in found} == {"a", "b"} and all(e["src_country"] == "TH" for e in found)

    stats = client.get("/api/stats", headers=auth).json()
    assert stats["top_countries"] == [{"key": "TH", "n": 2, "auth_failures": 2}]


def test_info_reports_demo_data_and_geoip(env, monkeypatch):
    client, tenant = env
    auth = {"Authorization": f"Bearer {create_token(Claims(sub='x', role='viewer', tenant=tenant))}"}
    monkeypatch.setattr(settings, "compose_profiles", "demo")
    assert client.get("/api/info", headers=auth).json() == {"demo_data": True, "geoip": True}
    monkeypatch.setattr(settings, "compose_profiles", "")
    assert client.get("/api/info", headers=auth).json()["demo_data"] is False
    assert client.get("/api/info").status_code == 401
