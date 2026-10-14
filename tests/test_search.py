"""Unit tests for the search SQL builder (no database)."""
from datetime import datetime, timedelta, timezone

import pytest

from app.search import SearchFilters, build_search, decode_cursor, encode_cursor, parse_ip_filter

END = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)
START = END - timedelta(hours=24)


def build(**kw):
    return build_search("demoA", SearchFilters(start=START, end=END, **kw))


def test_tenant_and_time_always_present():
    sql, params = build()
    assert sql.index("tenant = {tenant:String}") < sql.index("ts >= {start:")  # first condition
    assert (params["tenant"], params["start"], params["end"]) == ("demoA", START, END)


def test_user_values_are_parameters_not_sql():
    evil = "x'; DROP TABLE events; --"
    sql, params = build(q=evil, user=evil, host=evil, event_type=evil, tag=evil)
    assert "DROP TABLE" not in sql
    assert all(params[k] == evil for k in ("q", "user", "host", "event_type", "tag"))


def test_free_text_is_matched_literally():
    # A plain substring search (no LIKE), so "%" and "_" are just characters, not wildcards.
    sql, params = build(q="100%_x")
    assert params["q"] == "100%_x" and " LIKE " not in sql


def test_lists_use_in():
    sql, params = build(sources=["aws", "m365"])
    assert "source IN {sources:Array(String)}" in sql and params["sources"] == ["aws", "m365"]


def test_ip_filter_accepts_ip_and_cidr():
    assert parse_ip_filter("10.0.0.5") == "10.0.0.5/32"
    assert parse_ip_filter("10.1.2.3/8") == "10.0.0.0/8"
    with pytest.raises(ValueError):
        parse_ip_filter("nope")


def test_limit_fetches_one_extra():
    _, params = build(limit=50)
    assert params["limit"] == 51


def test_cursor_roundtrip():
    ts = datetime(2026, 10, 12, 8, 0, 1, 123456, tzinfo=timezone.utc)
    assert decode_cursor(encode_cursor(ts, 42)) == (ts, 42)
    with pytest.raises(ValueError):
        decode_cursor("garbage!!")
