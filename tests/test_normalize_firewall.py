from datetime import datetime, timezone

from app.normalizers import firewall

from conftest import NOW, sample_lines


def events():
    return [firewall.normalize(l, "demoA", now=NOW) for l in sample_lines("firewall.log")]


def test_every_sample_normalizes():
    evs = events()
    assert len(evs) == 5
    assert all(e.source == "firewall" and e.tenant == "demoA" for e in evs)


def test_deny_event_fields_and_aliases():
    e = events()[1]
    assert e.ts == datetime(2026, 10, 12, 8, 15, 7, tzinfo=timezone.utc)
    assert (e.vendor, e.product, e.host) == ("Fortinet", "FortiGate", "fw01")
    assert e.action == "deny" and "blocked" in e.tags
    assert (e.src_ip, e.src_port, e.dst_ip, e.dst_port, e.protocol) == ("203.0.113.45", 51234, "10.0.0.10", 22, "tcp")
    assert (e.rule_id, e.rule_name) == ("1001", "Block SSH from internet")
    assert e.severity == 5  # PRI 132 -> syslog warning(4) -> 5


def test_vendor_verbs_map_to_allow_deny():
    assert [e.action for e in events()] == ["allow", "deny", "deny", "allow", "deny"]


def test_ip_alias_maps_to_src_ip():
    assert events()[3].src_ip == "10.0.2.14"


def test_raw_keeps_original_line():
    line = sample_lines("firewall.log")[0]
    assert firewall.normalize(line, "demoA", now=NOW).raw == {"message": line}


def test_explicit_event_type_and_alert_severity():
    e = events()[4]
    assert (e.event_type, e.event_subtype, e.severity) == ("threat", "port_scan", 9)
