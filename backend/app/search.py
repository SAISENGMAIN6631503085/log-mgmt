"""Builds the ClickHouse SQL for event search. Pure (no DB), so the query logic is unit-testable.

Every user value is a typed parameter ({name:Type}), never pasted into the SQL text, so search
input can't inject SQL. Column names only come from the fixed code below.
"""
import base64
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SearchFilters:
    start: datetime
    end: datetime
    sources: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    severity_min: int | None = None
    src_ip: str | None = None   # IP or CIDR, e.g. "10.0.0.0/8"
    dst_ip: str | None = None
    user: str | None = None
    host: str | None = None
    country: str | None = None  # two-letter code of src_ip's country, e.g. "TH"
    event_type: str | None = None
    tag: str | None = None
    q: str | None = None        # free text, case-insensitive
    cursor: str | None = None   # from a previous page's next_cursor
    limit: int = 50


def encode_cursor(ts: datetime, event_id: int) -> str:
    return base64.urlsafe_b64encode(f"{ts.isoformat()}|{event_id}".encode()).decode()


def decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        ts, event_id = base64.urlsafe_b64decode(cursor.encode()).decode().split("|")
        return datetime.fromisoformat(ts), int(event_id)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("invalid cursor") from None


def parse_ip_filter(value: str) -> str:
    """Accept '1.2.3.4' or '10.0.0.0/8'; reject anything else with a clear error."""
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        raise ValueError(f"not an IP address or CIDR range: {value!r}") from None


# Free-text search looks in these columns, case-insensitively. raw (the original log) catches
# fields that aren't in the schema; the token index on raw lets ClickHouse skip blocks for words.
_Q_COLUMNS = ["event_type", "username", "host", "url", "rule_name", "process", "raw"]


def build_search(tenant: str, f: SearchFilters) -> tuple[str, dict[str, Any]]:
    params: dict[str, Any] = {"tenant": tenant, "start": f.start, "end": f.end, "limit": f.limit + 1}
    # tenant is always the first condition and is never optional.
    where = ["tenant = {tenant:String}",
             "ts >= {start:DateTime64(3, 'UTC')}", "ts < {end:DateTime64(3, 'UTC')}"]
    if f.sources:
        where.append("source IN {sources:Array(String)}")
        params["sources"] = f.sources
    if f.actions:
        where.append("action IN {actions:Array(String)}")
        params["actions"] = f.actions
    if f.severity_min is not None:
        where.append("severity >= {severity_min:UInt8}")
        params["severity_min"] = f.severity_min
    for column, value in (("src_ip", f.src_ip), ("dst_ip", f.dst_ip)):
        if value:
            # "Is this address inside that network", for a single IP (/32) or a range like 10.0.0.0/8.
            where.append(f"{column} IS NOT NULL AND isIPAddressInRange(assumeNotNull({column}), {{{column}:String}})")
            params[column] = parse_ip_filter(value)
    if f.user:
        where.append("lower(username) = lower({user:String})")  # exact but case-insensitive
        params["user"] = f.user
    if f.host:
        where.append("lower(host) = lower({host:String})")
        params["host"] = f.host
    if f.country:
        where.append("src_country = {country:String}")
        params["country"] = f.country.upper()
    if f.event_type:
        where.append("event_type = {event_type:String}")
        params["event_type"] = f.event_type
    if f.tag:
        where.append("has(tags, {tag:String})")
        params["tag"] = f.tag
    if f.q:
        where.append("(" + " OR ".join(f"positionCaseInsensitiveUTF8(ifNull({c}, ''), {{q:String}}) > 0"
                                       for c in _Q_COLUMNS) + ")")
        params["q"] = f.q
    if f.cursor:
        # Keyset paging: "rows after the last one I saw". Stays fast on deep pages and doesn't
        # skip or repeat rows when new events arrive between page loads.
        ts, event_id = decode_cursor(f.cursor)
        where.append("(ts, id) < ({cursor_ts:DateTime64(3, 'UTC')}, {cursor_id:UInt64})")
        params.update(cursor_ts=ts, cursor_id=event_id)
    # One extra row tells us whether there's a next page, without a count.
    sql = f"SELECT * FROM events WHERE {' AND '.join(where)} ORDER BY ts DESC, id DESC LIMIT {{limit:UInt32}}"
    return sql, params


def parse_ts(value: str) -> datetime:
    """ClickHouse's 'YYYY-MM-DD hh:mm:ss.mmm' (UTC) as an aware datetime."""
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


def row_to_api(r: dict[str, Any]) -> dict[str, Any]:
    """ClickHouse row -> common-schema JSON (`username` -> `user`, `ts` -> `@timestamp`, `tags` -> `_tags`)."""
    d = dict(r)
    d["@timestamp"] = parse_ts(d.pop("ts")).isoformat()
    d["user"] = d.pop("username")
    d["_tags"] = d.pop("tags")
    d["raw"] = json.loads(d["raw"])
    d.pop("ingested_at", None)
    d.pop("fingerprint", None)  # internal dedup hash, not part of the schema
    return d
