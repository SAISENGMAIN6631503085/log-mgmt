"""Alert rule: >= 5 failed logins from one src_ip per tenant within 5 minutes.

Integration tests run the real SQL against Postgres (skipped if it isn't running). Each test
uses its own random tenant, so the backend's own background worker (which may run at the
same time) can't change the outcome: de-duplication makes the result the same either way.
"""
import asyncio
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app import alerting, db
from app.alerting import merge_bursts, run_once
from app.auth import Claims, create_token
from app.config import settings
from app.main import app
from conftest import Event, delete_events, store_events

T0 = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)


# --- unit: burst merging -------------------------------------------------------

def _w(start_min, end_min, n, ip="1.1.1.1", tenant="t"):
    return {"tenant": tenant, "src_ip": ip, "n": n,
            "window_start": T0 + timedelta(minutes=start_min), "window_end": T0 + timedelta(minutes=end_min)}


def test_overlapping_windows_merge_into_one_burst():
    [b] = merge_bursts([_w(0, 2, 5), _w(1, 3, 6), _w(2, 4, 5)])
    assert (b["window_start"], b["window_end"], b["n"]) == (T0, T0 + timedelta(minutes=4), 6)


def test_separate_attacks_stay_separate():
    assert len(merge_bursts([_w(0, 2, 5), _w(60, 62, 5)])) == 2


def test_different_ips_and_tenants_never_merge():
    assert len(merge_bursts([_w(0, 2, 5, ip="1.1.1.1"), _w(0, 2, 5, ip="2.2.2.2")])) == 2
    assert len(merge_bursts([_w(0, 2, 5, tenant="a"), _w(0, 2, 5, tenant="b")])) == 2


# --- integration -------------------------------------------------------------

def _run(fn):
    async def go():
        conn = await asyncpg.connect(settings.database_dsn, timeout=2)
        await db._init_connection(conn)  # jsonb codec, same as the app's pool
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
    t = f"al_{uuid.uuid4().hex[:8]}"
    yield t

    async def cleanup(c):
        await c.execute("DELETE FROM alerts WHERE tenant LIKE $1", t + "%")
    _run(cleanup)
    delete_events([t, t + "_b"])


def add_failures(tenant, ip, minutes_ago: list[float], tag="auth_failure", user="administrator"):
    # Through the app's write path, so the events reach every event store (the alert worker
    # reads ClickHouse when it's configured). Distinct raw per event: they're separate logins.
    now = datetime.now(timezone.utc)
    store_events([Event(ts=now - timedelta(minutes=m), tenant=tenant, source="ad", action="login",
                        src_ip=ip, user=user, tags=[tag], raw={"n": i, "at": m})
                  for i, m in enumerate(minutes_ago)])


def alerts_for(tenant):
    return _run(lambda c: c.fetch("SELECT * FROM alerts WHERE tenant = $1 ORDER BY id", tenant))


def test_five_failures_in_five_minutes_alerts(tenant):
    add_failures(tenant, "203.0.113.50", [4, 3, 2, 1, 0])
    _run(run_once)
    [a] = alerts_for(tenant)
    assert (a["rule_id"], str(a["src_ip"]), a["event_count"], a["status"]) == ("brute_force_login", "203.0.113.50", 5, "open")
    assert a["details"]["users"] == ["administrator"]


def test_four_failures_do_not_alert(tenant):
    add_failures(tenant, "203.0.113.50", [3, 2, 1, 0])
    _run(run_once)
    assert alerts_for(tenant) == []


def test_five_failures_spread_over_more_than_five_minutes_do_not_alert(tenant):
    add_failures(tenant, "203.0.113.50", [8, 6, 4, 2, 0])  # never 5 inside one 5-min window
    _run(run_once)
    assert alerts_for(tenant) == []


def test_successful_logins_do_not_count(tenant):
    add_failures(tenant, "203.0.113.50", [4, 3, 2, 1, 0], tag="something_else")
    _run(run_once)
    assert alerts_for(tenant) == []


def test_counted_per_tenant(tenant):
    # Same IP, 3 failures in each of two tenants: 6 total, but neither tenant reaches 5.
    add_failures(tenant, "203.0.113.50", [3, 2, 1])
    add_failures(tenant + "_b", "203.0.113.50", [3, 2, 1])
    _run(run_once)
    assert alerts_for(tenant) == [] and alerts_for(tenant + "_b") == []


def test_counted_per_ip(tenant):
    add_failures(tenant, "203.0.113.50", [4, 3, 2])
    add_failures(tenant, "203.0.113.51", [4, 3])
    _run(run_once)
    assert alerts_for(tenant) == []


def test_no_duplicate_alert_on_repeated_runs(tenant):
    add_failures(tenant, "203.0.113.50", [4, 3, 2, 1, 0])
    _run(run_once)
    _run(run_once)
    assert len(alerts_for(tenant)) == 1


def test_ongoing_attack_extends_the_same_alert(tenant):
    add_failures(tenant, "203.0.113.50", [4, 3.5, 3, 2.5, 2])
    _run(run_once)
    add_failures(tenant, "203.0.113.50", [1.5, 1, 0.5, 0.2, 0])  # attack continues
    _run(run_once)
    [a] = alerts_for(tenant)
    assert a["event_count"] == 10  # all 10 failures fall inside one 5-minute window


def test_new_attack_after_quiet_period_alerts_again(tenant):
    add_failures(tenant, "203.0.113.50", [70, 69.5, 69, 68.5, 68])
    _run(run_once)
    add_failures(tenant, "203.0.113.50", [4, 3, 2, 1, 0])
    _run(run_once)
    assert len(alerts_for(tenant)) == 2


def test_late_arriving_logs_still_alert(tenant):
    # Event time 3 hours ago, but ingested just now (e.g. a file upload).
    add_failures(tenant, "203.0.113.50", [184, 183, 182, 181, 180])
    _run(run_once)
    [a] = alerts_for(tenant)
    assert a["window_end"] < datetime.now(timezone.utc) - timedelta(hours=2)


# --- webhook -------------------------------------------------------------------

class _Hook(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        _Hook.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def hook_server():
    _Hook.received = []
    server = HTTPServer(("127.0.0.1", 0), _Hook)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/hook"
    server.shutdown()


def test_webhook_posts_alert_json_once(tenant, hook_server, monkeypatch):
    monkeypatch.setattr(settings, "alert_webhook_url", hook_server)
    add_failures(tenant, "203.0.113.50", [4, 3, 2, 1, 0])
    _run(run_once)
    _run(run_once)
    mine = [p for p in _Hook.received if p["alert"]["tenant"] == tenant]
    assert len(mine) == 1
    assert mine[0]["type"] == "alert" and mine[0]["alert"]["src_ip"] == "203.0.113.50"
    assert alerts_for(tenant)[0]["webhook_sent_at"] is not None


def test_failed_webhook_is_retried_next_run(tenant, hook_server, monkeypatch):
    monkeypatch.setattr(settings, "alert_webhook_url", "http://127.0.0.1:1/unreachable")
    add_failures(tenant, "203.0.113.50", [4, 3, 2, 1, 0])
    _run(run_once)
    assert alerts_for(tenant)[0]["webhook_sent_at"] is None  # failed, alert still stored

    monkeypatch.setattr(settings, "alert_webhook_url", hook_server)
    _run(run_once)
    assert any(p["alert"]["tenant"] == tenant for p in _Hook.received)
    assert alerts_for(tenant)[0]["webhook_sent_at"] is not None


# --- alerts API ----------------------------------------------------------------

def _auth(role, tenant):
    return {"Authorization": f"Bearer {create_token(Claims(sub='t', role=role, tenant=tenant))}"}


def test_alerts_api_is_tenant_scoped_and_ack_is_admin_only(tenant):
    add_failures(tenant, "203.0.113.50", [4, 3, 2, 1, 0])
    add_failures(tenant + "_b", "203.0.113.60", [4, 3, 2, 1, 0])
    _run(run_once)
    with TestClient(app) as client:
        viewer = _auth("viewer", tenant)
        alerts = client.get("/api/alerts", headers=viewer).json()["alerts"]
        assert [a["src_ip"] for a in alerts] == ["203.0.113.50"]
        assert client.get(f"/api/alerts?tenant={tenant}_b", headers=viewer).status_code == 403

        alert_id = alerts[0]["id"]
        assert client.post(f"/api/alerts/{alert_id}/ack", headers=viewer).status_code == 403

        admin_other = _auth("admin", tenant + "_b")  # admin whose default tenant is the other one
        assert client.post(f"/api/alerts/{alert_id}/ack", headers=admin_other).status_code == 404
        r = client.post(f"/api/alerts/{alert_id}/ack?tenant={tenant}", headers=admin_other)
        assert r.status_code == 200 and r.json()["status"] == "acknowledged"
        assert client.get("/api/alerts?status=open", headers=viewer).json()["alerts"] == []
