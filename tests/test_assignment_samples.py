"""The exact sample logs from the assignment PDF (section 4), which reviewers will send.

Unit part: every sample normalizes to the right fields. Integration part (needs Postgres):
the samples go through POST /ingest as written, dated 2025, and become searchable.
"""
import asyncio
import uuid
from datetime import datetime, timezone

import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.api_keys import create_key
from app.config import settings
from app.ingest_parsing import classify_syslog
from app.main import app
from app.normalizers import ad, api, aws, crowdstrike, firewall, m365, network

NOW = datetime(2025, 8, 21, tzinfo=timezone.utc)  # the samples' "Aug 20" is in the past

FW = "<134>Aug 20 12:44:56 fw01 vendor=demo product=ngfw action=deny src=10.0.1.10 dst=8.8.8.8 spt=5353 dpt=53 proto=udp msg=DNS blocked policy=Block-DNS"
NET = "<190>Aug 20 13:01:02 r1 if=ge-0/0/1 event=link-down mac=aa:bb:cc:dd:ee:ff reason=carrier-loss"
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


# --- unit: normalization -------------------------------------------------------------

def test_4_1_firewall_syslog():
    assert classify_syslog(FW) == "firewall"
    e = firewall.normalize(FW, "demoA", now=NOW)
    assert (e.action, e.src_ip, e.src_port, e.dst_ip, e.dst_port, e.protocol) == ("deny", "10.0.1.10", 5353, "8.8.8.8", 53, "udp")
    assert (e.vendor, e.product, e.rule_name, e.host) == ("demo", "ngfw", "Block-DNS", "fw01")


def test_4_2_network_syslog():
    assert classify_syslog(NET) == "network"
    e = network.normalize(NET, "demoA", now=NOW)
    assert (e.event_type, e.event_subtype, e.host) == ("link-down", "ge-0/0/1", "r1")


def test_4_3_api():
    e = api.normalize(API, "demoA")
    assert (e.event_type, e.user, e.src_ip, e.action, e.event_subtype) == ("app_login_failed", "alice", "203.0.113.7", "login", "wrong_password")
    assert "auth_failure" in e.tags
    assert e.ts == datetime(2025, 8, 20, 7, 20, tzinfo=timezone.utc)


def test_4_4_crowdstrike_flat():
    e = crowdstrike.normalize(CS, "demoA")
    assert (e.event_type, e.host, e.process, e.severity, e.action) == ("malware_detected", "WIN10-01", "powershell.exe", 8, "quarantine")
    assert "quarantined" in e.tags and e.raw["sha256"] == "abc..."


def test_4_5_aws_flat():
    e = aws.normalize(AWS, "demoB")
    assert (e.event_type, e.action, e.user) == ("CreateUser", "create", "admin")
    assert (e.cloud_service, e.cloud_account_id, e.cloud_region) == ("iam", "123456789012", "ap-southeast-1")
    assert e.raw == AWS  # the whole original payload is kept


def test_4_6_m365_flat():
    e = m365.normalize(M365, "demoB")
    assert (e.event_type, e.action, e.user, e.src_ip, e.cloud_service) == ("UserLoggedIn", "login", "bob@demo.local", "198.51.100.23", "Exchange")
    assert "auth_failure" not in e.tags


def test_4_6_m365_flat_failed_status_is_auth_failure():
    e = m365.normalize(M365 | {"status": "Failed"}, "demoB")
    assert "auth_failure" in e.tags


def test_4_7_ad_flat_4625():
    e = ad.normalize(AD, "demoA")
    assert (e.event_type, e.event_subtype, e.action, e.user, e.host, e.src_ip) == (
        "logon_failure", "4625", "login", "demo\\eve", "DC01", "203.0.113.77")
    assert "auth_failure" in e.tags


# --- integration: POST /ingest exactly as the assignment describes ------------------------

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
    with TestClient(app) as client:
        yield client, tenants, k
    _db(lambda c: c.execute("DELETE FROM events WHERE tenant = ANY($1)", list(tenants.values())))
    _db(lambda c: c.execute("DELETE FROM api_keys WHERE tenant = ANY($1)", list(tenants.values())))
    _db(lambda c: c.execute("DELETE FROM alerts WHERE tenant = ANY($1)", list(tenants.values())))


@pytest.mark.parametrize("sample", [API, CS, AWS, M365, AD], ids=["api", "crowdstrike", "aws", "m365", "ad"])
def test_post_ingest_with_assignment_sample(keys, sample):
    client, tenants, k = keys
    body = sample | {"tenant": tenants[sample["tenant"]]}
    r = client.post("/ingest", json=body, headers={"X-API-Key": k[sample["tenant"]]})
    assert r.status_code == 200, r.text
    res = r.json()
    # Dated 2025: stored at receipt time and flagged, not rejected.
    assert (res["accepted"], res["time_adjusted"], res["rejected_count"]) == (1, 1, 0)

    from app.auth import Claims, create_token
    token = create_token(Claims(sub="t", role="viewer", tenant=tenants[sample["tenant"]]))
    found = client.get("/api/events", params={"source": sample["source"]}, headers={"Authorization": f"Bearer {token}"}).json()
    [e] = found["events"]
    assert e["source"] == sample["source"]  # the body's "source" picked the normalizer
    assert "time_adjusted" in e["_tags"] and e["raw"]["@timestamp"] == sample["@timestamp"]


def test_sample_with_other_tenants_key_is_rejected(keys):
    client, tenants, k = keys
    body = AWS | {"tenant": tenants["demoB"]}
    res = client.post("/ingest", json=body, headers={"X-API-Key": k["demoA"]}).json()
    assert res["accepted"] == 0 and res["rejected_count"] == 1
