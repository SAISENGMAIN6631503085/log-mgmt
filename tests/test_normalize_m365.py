from datetime import datetime, timezone

from app.normalizers import m365

from conftest import sample_json


def events():
    return [m365.normalize(r, "demoB") for r in sample_json("m365_audit.json")]


def test_every_sample_normalizes():
    assert len(events()) == 4


def test_successful_login():
    e = events()[0]
    assert (e.action, e.tags, e.user) == ("login", [], "erin@contoso.com")
    assert e.ts == datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc)  # zone-less -> UTC


def test_failed_login_is_auth_failure():
    e = events()[1]
    assert (e.action, e.event_subtype, e.src_ip) == ("login", "InvalidPassword", "203.0.113.120")
    assert "auth_failure" in e.tags


def test_failed_status_alone_counts_as_failed_login():
    e = m365.normalize({"CreationTime": "2026-10-12T09:00:00", "Operation": "UserLoggedIn",
                        "ResultStatus": "Failed", "Workload": "AzureActiveDirectory"}, "t")
    assert e.action == "login" and "auth_failure" in e.tags


def test_file_deleted():
    e = events()[2]
    assert (e.action, e.cloud_service) == ("delete", "SharePoint")
    assert e.url.endswith("salaries.xlsx")


def test_forwarding_inbox_rule_and_ip_with_port():
    e = events()[3]
    assert e.action == "create" and "mail_forwarding_rule" in e.tags and e.severity == 6
    assert e.src_ip == "203.0.113.120"
