from fastapi.testclient import TestClient

from app import db
from app.main import app


def _client(monkeypatch, db_up: bool) -> TestClient:
    # Unit tests must not need a running Postgres, so stub out the pool lifecycle and ping.
    async def noop():
        return None

    async def fake_ping():
        return db_up

    monkeypatch.setattr(db, "connect", noop)
    monkeypatch.setattr(db, "disconnect", noop)
    monkeypatch.setattr(db, "ping", fake_ping)
    return TestClient(app)


def test_health_ok(monkeypatch):
    with _client(monkeypatch, db_up=True) as client:
        r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "database": "ok"}


def test_health_reports_db_down(monkeypatch):
    with _client(monkeypatch, db_up=False) as client:
        r = client.get("/health")
    assert r.status_code == 503
    assert r.json()["database"] == "down"
