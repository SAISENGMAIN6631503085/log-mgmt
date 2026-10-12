from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.normalizers import normalize
from app.normalizers.common import Event, clean_ip, parse_ts, to_port, unify_aliases


def test_unify_aliases_maps_vendor_names_to_schema():
    assert unify_aliases({"ip": "1.2.3.4", "dst": "5.6.7.8", "spt": "1", "dpt": "2", "proto": "tcp"}) == {
        "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "src_port": "1", "dst_port": "2", "protocol": "tcp"}


def test_unify_aliases_explicit_schema_key_wins():
    assert unify_aliases({"src_ip": "1.1.1.1", "ip": "2.2.2.2"})["src_ip"] == "1.1.1.1"
    assert unify_aliases({"ip": "2.2.2.2", "src_ip": "1.1.1.1"})["src_ip"] == "1.1.1.1"


@pytest.mark.parametrize("value,expected", [
    ("10.0.0.1", "10.0.0.1"),
    ("203.0.113.120:51515", "203.0.113.120"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("2001:db8::1", "2001:db8::1"),
    ("-", None), ("", None), (None, None),
    ("ec2.amazonaws.com", None),
])
def test_clean_ip(value, expected):
    assert clean_ip(value) == expected


@pytest.mark.parametrize("value,expected", [("443", 443), ("0", None), ("-", None), ("70000", None), (22, 22)])
def test_to_port(value, expected):
    assert to_port(value) == expected


@pytest.mark.parametrize("value", [
    "2026-10-12T08:00:00Z", "2026-10-12T08:00:00", "2026-10-12T10:00:00+02:00",
    1791792000, 1791792000000,
])
def test_parse_ts_variants_all_utc(value):
    assert parse_ts(value) == datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc)


def test_parse_ts_rejects_missing():
    with pytest.raises(ValueError):
        parse_ts(None)


def test_event_rejects_out_of_range_severity():
    with pytest.raises(ValidationError):
        Event(ts=datetime.now(timezone.utc), tenant="t", source="api", severity=11, raw={})


def test_event_rejects_invalid_ip():
    with pytest.raises(ValidationError):
        Event(ts=datetime.now(timezone.utc), tenant="t", source="api", src_ip="not-an-ip", raw={})


def test_registry_rejects_unknown_source():
    with pytest.raises(ValueError, match="unknown source"):
        normalize("mainframe", {}, "t")
