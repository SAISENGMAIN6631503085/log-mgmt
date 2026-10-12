from datetime import datetime, timezone

from app.normalizers import api

from conftest import NOW, sample_json


def events():
    return [api.normalize(p, "demoA") for p in sample_json("api_events.json")]


def test_every_sample_normalizes():
    assert len(events()) == 5


def test_login_failed_is_auth_failure():
    e = events()[1]
    assert e.action == "login" and "auth_failure" in e.tags
    assert (e.src_ip, e.user, e.http_method, e.url, e.status_code) == ("203.0.113.77", "alice", "POST", "/api/v1/login", 401)
    assert e.event_subtype == "bad_password" and e.severity == 5


def test_non_auth_failure_is_not_tagged_auth_failure():
    e = events()[2]  # payment_failed
    assert e.action is None and e.tags == []
    assert e.severity == 6  # 502


def test_login_success_and_logout():
    evs = events()
    assert (evs[0].action, evs[0].tags) == ("login", [])
    assert evs[4].action == "logout"


def test_tenant_in_body_is_ignored():
    e = api.normalize({"timestamp": "2026-10-12T08:00:00Z", "tenant": "demoB", "event_type": "x"}, "demoA")
    assert e.tenant == "demoA"
    assert e.raw["tenant"] == "demoB"  # still visible in the original payload


def test_missing_timestamp_uses_receipt_time():
    assert api.normalize({"event_type": "x"}, "t", now=NOW).ts == NOW


def test_explicit_severity_is_kept_and_bad_one_is_derived():
    assert api.normalize({"timestamp": "2026-10-12T08:00:00Z", "severity": 9}, "t").severity == 9
    assert api.normalize({"timestamp": "2026-10-12T08:00:00Z", "severity": 99}, "t").severity == 2


def test_timestamp_parsed_as_utc():
    assert events()[0].ts == datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc)
