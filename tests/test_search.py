"""Unit tests for the search SQL builder (no database)."""
from datetime import datetime, timedelta, timezone

import pytest

from app.search import SearchFilters, build_search, decode_cursor, encode_cursor, parse_ip_filter

END = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)
START = END - timedelta(hours=24)


def build(**kw):
    return build_search("demoA", SearchFilters(start=START, end=END, **kw))


def test_tenant_and_time_always_present():
    sql, args = build()
    assert "tenant = $1" in sql and args[:3] == ["demoA", START, END]


def test_user_values_are_parameters_not_sql():
    evil = "x'; DROP TABLE events; --"
    sql, args = build(q=evil, user=evil, host=evil, event_type=evil, tag=evil)
    assert "DROP TABLE" not in sql
    assert any("DROP TABLE" in str(a) for a in args)


def test_like_wildcards_escaped():
    _, args = build(q="100%_x")
    assert "%100\\%\\_x%" in args


def test_lists_use_any():
    sql, args = build(sources=["aws", "m365"])
    assert "source = ANY($4)" in sql and ["aws", "m365"] in args


def test_ip_filter_accepts_ip_and_cidr():
    assert parse_ip_filter("10.0.0.5") == "10.0.0.5/32"
    assert parse_ip_filter("10.1.2.3/8") == "10.0.0.0/8"
    with pytest.raises(ValueError):
        parse_ip_filter("nope")


def test_limit_fetches_one_extra():
    _, args = build(limit=50)
    assert args[-1] == 51


def test_cursor_roundtrip():
    ts = datetime(2026, 10, 12, 8, 0, 1, 123456, tzinfo=timezone.utc)
    assert decode_cursor(encode_cursor(ts, 42)) == (ts, 42)
    with pytest.raises(ValueError):
        decode_cursor("garbage!!")
