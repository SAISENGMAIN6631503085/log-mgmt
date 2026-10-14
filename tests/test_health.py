from fastapi.testclient import TestClient

from app import db
from app.clickhouse import ch
from app.main import app


def _client(monkeypatch, db_up: bool, events_up: bool = True) -> TestClient:
    # Unit tests must not need running databases, so stub out the pool lifecycle and pings.
    async def noop():
        return None

    async def fake_ping():
        return db_up

    async def fake_ch_ping():
        return events_up

    monkeypatch.setattr(db, "connect", noop)
    monkeypatch.setattr(db, "disconnect", noop)
    monkeypatch.setattr(db, "ping", fake_ping)
    monkeypatch.setattr(ch, "ping", fake_ch_ping)
    return TestClient(app)


def test_health_ok(monkeypatch):
    with _client(monkeypatch, db_up=True) as client:
        r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "database": "ok", "event_store": "ok"}


def test_health_reports_db_down(monkeypatch):
    with _client(monkeypatch, db_up=False) as client:
        r = client.get("/health")
    assert r.status_code == 503
    assert r.json()["database"] == "down"


def test_health_reports_event_store_down(monkeypatch):
    with _client(monkeypatch, db_up=True, events_up=False) as client:
        r = client.get("/health")
    assert r.status_code == 503
    assert r.json()["event_store"] == "down" and r.json()["database"] == "ok"
