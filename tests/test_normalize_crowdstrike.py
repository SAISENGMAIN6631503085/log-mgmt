from datetime import datetime, timezone

from app.normalizers import crowdstrike

from conftest import sample_ndjson


def events():
    return [crowdstrike.normalize(p, "demoA") for p in sample_ndjson("crowdstrike_detections.ndjson")]


def test_every_sample_normalizes():
    assert len(events()) == 2


def test_quarantined_detection():
    e = events()[0]
    assert e.ts == datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc)  # from epoch ms
    assert (e.vendor, e.product, e.event_type, e.event_subtype) == ("CrowdStrike", "Falcon", "detection", "Credential Access")
    assert (e.host, e.user, e.process, e.src_ip) == ("WS-042", "bob", "mimikatz.exe", "10.0.1.42")
    assert (e.rule_name, e.rule_id) == ("Mimikatz credential theft", "ldt:a1b2c3:1001")
    assert e.action == "quarantine" and "quarantined" in e.tags
    assert e.severity == 10  # Falcon 5 -> 10


def test_detection_without_quarantine_is_alert():
    e = events()[1]
    assert e.action == "alert" and e.severity == 6 and "quarantined" not in e.tags
