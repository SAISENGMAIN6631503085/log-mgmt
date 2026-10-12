from app.normalizers import ad

from conftest import sample_csv


def events():
    return [ad.normalize(r, "demoA") for r in sample_csv("ad_security.csv")]


def test_every_row_normalizes():
    assert len(events()) == 11


def test_4625_is_failed_login():
    e = events()[1]
    assert (e.event_type, e.event_subtype, e.action) == ("logon_failure", "4625", "login")
    assert "auth_failure" in e.tags
    assert (e.user, e.src_ip, e.src_port, e.host) == ("administrator", "203.0.113.50", 51001, "DC01.corp.local")


def test_sample_contains_brute_force_burst():
    # The alert rule needs >= 5 failures from one IP within 5 minutes; the sample provides 6.
    fails = [e for e in events() if "auth_failure" in e.tags and e.src_ip == "203.0.113.50"]
    assert len(fails) == 6
    assert (fails[-1].ts - fails[0].ts).total_seconds() <= 300


def test_other_event_ids():
    by_id = {e.event_subtype: e for e in events()}
    assert by_id["4624"].action == "login" and by_id["4624"].tags == []
    assert by_id["4634"].action == "logout"
    assert by_id["4720"].action == "create"
    assert by_id["4726"].action == "delete"
    assert by_id["4740"].action == "alert" and "account_lockout" in by_id["4740"].tags


def test_dash_placeholders_become_none():
    e = events()[7]  # 4740: IpAddress and IpPort are "-"
    assert e.src_ip is None and e.src_port is None


def test_unknown_event_id_still_normalizes():
    e = ad.normalize({"TimeCreated": "2026-10-12T10:00:00Z", "EventID": "4688"}, "t")
    assert (e.event_type, e.action) == ("event_4688", None)


def test_tags_are_not_shared_between_events():
    a, b = events()[1], events()[2]
    a.tags.append("x")
    assert "x" not in b.tags
