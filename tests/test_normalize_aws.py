from app.normalizers import aws

from conftest import sample_json


def events():
    return [aws.normalize(r, "demoA") for r in aws.iter_records(sample_json("aws_cloudtrail.json"))]


def test_every_record_normalizes():
    assert len(events()) == 6


def test_failed_console_login():
    e = events()[0]
    assert (e.event_type, e.action, e.user, e.src_ip) == ("ConsoleLogin", "login", "carol", "203.0.113.99")
    assert "auth_failure" in e.tags and e.severity == 5
    assert (e.cloud_account_id, e.cloud_region, e.cloud_service) == ("123456789012", "us-east-1", "signin")


def test_root_login_is_flagged():
    e = events()[1]
    assert e.tags == ["root_activity"] and e.severity == 7 and e.user == "root"


def test_create_and_delete_actions():
    evs = events()
    assert (evs[2].action, evs[2].cloud_service, evs[2].cloud_region) == ("create", "ec2", "eu-west-1")
    assert (evs[3].action, evs[3].severity) == ("delete", 4)


def test_access_denied_overrides_action():
    e = events()[4]
    assert e.action == "deny" and "access_denied" in e.tags and e.event_subtype == "AccessDenied"


def test_service_caller_hostname_is_not_an_ip():
    e = events()[5]
    assert e.src_ip is None and e.host == "events.amazonaws.com" and e.user == "events.amazonaws.com"


def test_iter_records_accepts_list_and_single():
    assert len(list(aws.iter_records([{}, {}]))) == 2
    assert len(list(aws.iter_records({"eventName": "x"}))) == 1
