"""The exact sample logs from the assignment PDF (section 4), which reviewers will send: they go
through POST /ingest as written, dated 2025, and become searchable (needs the running services).

How each sample is normalized is tested in Go, next to the code: ingest/normalize/assignment_samples_test.go.
"""
import asyncio
import uuid

import asyncpg
import httpx
import pytest
from fastapi.testclient import TestClient

from app.api_keys import create_key
from app.config import settings
from app.main import app
from conftest import delete_events, ingest_client

API = {"tenant": "demoA", "source": "api", "event_type": "app_login_failed", "user": "alice", "ip": "203.0.113.7",
       "reason": "wrong_password", "@timestamp": "2025-08-20T07:20:00Z"}
CS = {"tenant": "demoA", "source": "crowdstrike", "event_type": "malware_detected", "host": "WIN10-01",
      "process": "powershell.exe", "severity": 8, "sha256": "abc...", "action": "quarantine", "@timestamp": "2025-08-20T08:00:00Z"}
AWS = {"tenant": "demoB", "source": "aws", "cloud": {"service": "iam", "account_id": "123456789012", "region": "ap-southeast-1"},
       "event_type": "CreateUser", "user": "admin", "@timestamp": "2025-08-20T09:10:00Z",
       "raw": {"eventName": "CreateUser", "requestParameters": {"userName": "temp-user"}}}
M365 = {"tenant": "demoB", "source": "m365", "event_type": "UserLoggedIn", "user": "bob@demo.local", "ip": "198.51.100.23",
        "status": "Success", "workload": "Exchange", "@timestamp": "2025-08-20T10:05:00Z"}
AD = {"tenant": "demoA", "source": "ad", "event_id": 4625, "event_type": "LogonFailed", "user": "demo\\eve", "host": "DC01",
      "ip": "203.0.113.77", "logon_type": 3, "@timestamp": "2025-08-20T11:11:11Z"}


def _db(fn):
    async def run():
        c = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            return await fn(c)
        finally:
            await c.close()
    return asyncio.run(run())


@pytest.fixture
def keys():
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")
    # The samples name tenants demoA/demoB; give each run fresh tenants by rewriting that field.
    sfx = uuid.uuid4().hex[:6]
    tenants = {"demoA": f"sa_{sfx}", "demoB": f"sb_{sfx}"}
    k = {name: _db(lambda c, t=t: create_key(c, t, "test")) for name, t in tenants.items()}
    with ingest_client() as ingest, TestClient(app) as api:
        try:
            ingest.get("/health")
        except httpx.HTTPError:
            pytest.skip("ingest service not reachable; run `make up` first")
        yield ingest, api, tenants, k
    _db(lambda c: c.execute("DELETE FROM api_keys WHERE tenant = ANY($1)", list(tenants.values())))
    _db(lambda c: c.execute("DELETE FROM alerts WHERE tenant = ANY($1)", list(tenants.values())))
    delete_events(list(tenants.values()))


@pytest.mark.parametrize("sample", [API, CS, AWS, M365, AD], ids=["api", "crowdstrike", "aws", "m365", "ad"])
def test_post_ingest_with_assignment_sample(keys, sample):
    ingest, api, tenants, k = keys
    body = sample | {"tenant": tenants[sample["tenant"]]}
    r = ingest.post("/ingest", json=body, headers={"X-API-Key": k[sample["tenant"]]})
    assert r.status_code == 200, r.text
    res = r.json()
    # Dated 2025: stored at receipt time and flagged, not rejected.
    assert (res["accepted"], res["time_adjusted"], res["rejected_count"]) == (1, 1, 0)

    from app.auth import Claims, create_token
    token = create_token(Claims(sub="t", role="viewer", tenant=tenants[sample["tenant"]]))
    found = api.get("/api/events", params={"source": sample["source"]}, headers={"Authorization": f"Bearer {token}"}).json()
    [e] = found["events"]
    assert e["source"] == sample["source"]  # the body's "source" picked the normalizer
    assert "time_adjusted" in e["_tags"] and e["raw"]["@timestamp"] == sample["@timestamp"]


def test_sample_with_other_tenants_key_is_rejected(keys):
    ingest, _, tenants, k = keys
    body = AWS | {"tenant": tenants["demoB"]}
    res = ingest.post("/ingest", json=body, headers={"X-API-Key": k["demoA"]}).json()
    assert res["accepted"] == 0 and res["rejected_count"] == 1
