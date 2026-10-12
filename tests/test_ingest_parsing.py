from datetime import datetime, timedelta, timezone

import pytest

from app.events_store import check_ts_window
from app.ingest_parsing import classify_syslog, parse_upload, split_payloads

from conftest import SAMPLES

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("name,source,count", [
    ("aws_cloudtrail.json", "aws", 6),          # {"Records": [...]} unwrapped
    ("m365_audit.json", "m365", 4),
    ("api_events.json", "api", 5),
    ("crowdstrike_detections.ndjson", "crowdstrike", 2),
    ("ad_security.csv", "ad", 11),
    ("firewall.log", "firewall", 5),
    ("network.log", "network", 4),
])
def test_parse_every_sample_file(name, source, count):
    assert len(parse_upload(name, (SAMPLES / name).read_bytes(), source)) == count


def test_csv_with_excel_bom():
    rows = parse_upload("x.csv", "﻿EventID,Computer\n4625,DC01\n".encode(), "ad")
    assert rows == [{"EventID": "4625", "Computer": "DC01"}]


def test_ndjson_saved_as_json():
    assert len(parse_upload("x.json", b'{"a":1}\n{"a":2}\n', "api")) == 2


def test_single_json_object_file():
    assert parse_upload("x.json", b'{"a":1}', "api") == [{"a": 1}]


def test_unknown_extension_rejected():
    with pytest.raises(ValueError, match="unsupported file type"):
        parse_upload("x.bin", b"\x00garbage", "api")


def test_split_payloads():
    assert split_payloads("api", {"a": 1}) == [{"a": 1}]
    assert split_payloads("api", [{"a": 1}, {"a": 2}]) == [{"a": 1}, {"a": 2}]
    assert split_payloads("aws", {"Records": [{"x": 1}]}) == [{"x": 1}]
    with pytest.raises(ValueError):
        split_payloads("api", 42)


@pytest.mark.parametrize("line,expected", [
    ("<134>Oct 12 08:00:00 fw01 action=deny src=1.2.3.4 dst=5.6.7.8", "firewall"),
    ("<134>Oct 12 08:00:00 fw01 action=accept ip=1.2.3.4", "firewall"),
    ("<187>Oct 12 08:00:00 sw %LINK-3-UPDOWN: event_type=link_down", "network"),
    ("<189>Oct 12 08:00:00 rtr event_type=config_change user=x src=1.2.3.4", "network"),  # no action
    ("garbage", "network"),
])
def test_classify_syslog(line, expected):
    assert classify_syslog(line) == expected


def test_ts_window():
    assert check_ts_window(NOW, 7, NOW) is None
    assert check_ts_window(NOW - timedelta(days=6), 7, NOW) is None
    assert "retention" in check_ts_window(NOW - timedelta(days=8), 7, NOW)
    assert "future" in check_ts_window(NOW + timedelta(days=2), 7, NOW)
