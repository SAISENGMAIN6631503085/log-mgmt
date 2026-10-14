"""The extra alert rules (firewall scan, malware) and per-tenant rule settings.

Integration tests against Postgres (skipped if it isn't running); each uses its own random tenant.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app import db
from app.alerting import run_once
from app.auth import Claims, create_token
from app.config import settings
from app.main import app
from conftest import Event, delete_events, store_events


def _run(fn):
    async def go():
        conn = await asyncpg.connect(settings.database_dsn, timeout=2)
        await db._init_connection(conn)
        try:
            return await fn(conn)
        finally:
            await conn.close()
    return asyncio.run(go())


@pytest.fixture
def tenant():
    try:
        _run(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")
    t = f"ru_{uuid.uuid4().hex[:8]}"
    yield t

    async def cleanup(c):
        for table in ("alerts", "rule_settings"):
            await c.execute(f"DELETE FROM {table} WHERE tenant LIKE $1", t + "%")
    _run(cleanup)
    delete_events([t, t + "_b"])


def add(tenant, n, *, source, tags=(), severity=None, ip=None, host=None, minutes_ago=0.0):
    # Through the app's write path, so the events reach every event store.
    now = datetime.now(timezone.utc)
    store_events([Event(ts=now - timedelta(minutes=minutes_ago, seconds=i), tenant=tenant, source=source,
                        severity=severity, src_ip=ip, host=host, tags=list(tags), raw={"i": i, "at": minutes_ago})
                  for i in range(n)])


def alerts_for(tenant):
    return _run(lambda c: c.fetch("SELECT * FROM alerts WHERE tenant = $1 ORDER BY id", tenant))


def set_rule(tenant, rule_id, enabled, threshold):
    _run(lambda c: c.execute(
        "INSERT INTO rule_settings (tenant, rule_id, enabled, threshold) VALUES ($1, $2, $3, $4)",
        tenant, rule_id, enabled, threshold))


# --- firewall scan -------------------------------------------------------------

def test_twenty_blocked_connections_from_one_ip_alert(tenant):
    add(tenant, 20, source="firewall", tags=["blocked"], ip="203.0.113.9")
    _run(run_once)
    [a] = alerts_for(tenant)
    assert (a["rule_id"], str(a["src_ip"]), a["group_key"], a["event_count"]) == ("firewall_scan", "203.0.113.9", "203.0.113.9", 20)


def test_nineteen_blocked_connections_do_not_alert(tenant):
    add(tenant, 19, source="firewall", tags=["blocked"], ip="203.0.113.9")
    _run(run_once)
    assert alerts_for(tenant) == []


def test_allowed_traffic_does_not_count_as_a_scan(tenant):
    add(tenant, 30, source="firewall", ip="203.0.113.9")  # no "blocked" tag
    _run(run_once)
    assert alerts_for(tenant) == []


# --- malware -------------------------------------------------------------------

def test_high_severity_crowdstrike_detection_alerts_per_host(tenant):
    add(tenant, 1, source="crowdstrike", severity=8, host="WIN10-01")
    _run(run_once)
    [a] = alerts_for(tenant)
    assert (a["rule_id"], a["group_key"], a["src_ip"]) == ("malware_detected", "WIN10-01", None)
    assert a["details"]["hosts"] == ["WIN10-01"]


def test_low_severity_detection_does_not_alert(tenant):
    add(tenant, 3, source="crowdstrike", severity=5, host="WIN10-01")
    _run(run_once)
    assert alerts_for(tenant) == []


def test_repeated_detections_on_one_host_are_one_alert(tenant):
    add(tenant, 1, source="crowdstrike", severity=8, host="WIN10-01")
    _run(run_once)
    add(tenant, 1, source="crowdstrike", severity=9, host="WIN10-01", minutes_ago=-0.1)
    _run(run_once)
    assert len(alerts_for(tenant)) == 1


# --- per-tenant settings ---------------------------------------------------------

def test_disabled_rule_does_not_alert_for_that_tenant_only(tenant):
    set_rule(tenant, "brute_force_login", False, 5)
    for t in (tenant, tenant + "_b"):
        add(t, 6, source="ad", tags=["auth_failure"], ip="203.0.113.50")
    _run(run_once)
    assert alerts_for(tenant) == []
    assert [a["rule_id"] for a in alerts_for(tenant + "_b")] == ["brute_force_login"]


def test_lower_threshold_applies(tenant):
    set_rule(tenant, "brute_force_login", True, 3)
    add(tenant, 3, source="ad", tags=["auth_failure"], ip="203.0.113.50")
    _run(run_once)
    [a] = alerts_for(tenant)
    assert a["event_count"] == 3 and a["details"]["threshold"] == 3


# --- rules API -----------------------------------------------------------------

def _auth(role, tenant):
    return {"Authorization": f"Bearer {create_token(Claims(sub='t', role=role, tenant=tenant))}"}


def test_rules_api(tenant):
    with TestClient(app) as client:
        viewer, admin = _auth("viewer", tenant), _auth("admin", tenant)
        rules = client.get("/api/rules", headers=viewer).json()["rules"]
        assert [r["id"] for r in rules] == ["brute_force_login", "firewall_scan", "malware_detected"]
        assert all(r["enabled"] and r["threshold"] == r["default_threshold"] for r in rules)
        assert client.get(f"/api/rules?tenant={tenant}_b", headers=viewer).status_code == 403

        body = {"enabled": False, "threshold": 10}
        assert client.put("/api/rules/firewall_scan", json=body, headers=viewer).status_code == 403
        r = client.put("/api/rules/firewall_scan", json=body, headers=admin)
        assert r.status_code == 200 and (r.json()["enabled"], r.json()["threshold"]) == (False, 10)
        assert client.put("/api/rules/nope", json=body, headers=admin).status_code == 404
        assert client.put("/api/rules/firewall_scan", json={"enabled": True, "threshold": 0}, headers=admin).status_code == 422

        # The change is per tenant: another tenant still has the defaults.
        other = client.get(f"/api/rules?tenant={tenant}_b", headers=admin).json()["rules"]
        assert next(r for r in other if r["id"] == "firewall_scan")["enabled"] is True
