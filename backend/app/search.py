"""Builds the SQL for event search. Pure (no DB), so the query logic is unit-testable.

Every user value goes in as a $n parameter, never into the SQL text, so search input
can't inject SQL. Column names only come from the fixed code below.
"""
import base64
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime


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


def _like_escape(text: str) -> str:
    # So a search for "100%" matches the literal text instead of "100<anything>".
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# Columns searched by the free-text box. raw::text catches fields that aren't in the schema;
# it's a sequential scan, but only within one tenant's time window (partition pruning + index).
_Q_COLUMNS = ["event_type", "username", "host", "url", "rule_name", "process", "raw::text"]


def build_search(tenant: str, f: SearchFilters) -> tuple[str, list]:
    args: list = []

    def p(value) -> str:
        args.append(value)
        return f"${len(args)}"

    # tenant is always the first condition and is never optional.
    where = [f"tenant = {p(tenant)}", f"ts >= {p(f.start)}", f"ts < {p(f.end)}"]
    if f.sources:
        where.append(f"source = ANY({p(f.sources)})")
    if f.actions:
        where.append(f"action = ANY({p(f.actions)})")
    if f.severity_min is not None:
        where.append(f"severity >= {p(f.severity_min)}")
    if f.src_ip:
        where.append(f"src_ip <<= {p(parse_ip_filter(f.src_ip))}::inet")  # <<= : "is inside network"
    if f.dst_ip:
        where.append(f"dst_ip <<= {p(parse_ip_filter(f.dst_ip))}::inet")
    if f.user:
        where.append(f"username ILIKE {p(_like_escape(f.user))}")  # exact but case-insensitive
    if f.host:
        where.append(f"host ILIKE {p(_like_escape(f.host))}")
    if f.event_type:
        where.append(f"event_type = {p(f.event_type)}")
    if f.tag:
        where.append(f"_tags @> ARRAY[{p(f.tag)}]::text[]")
    if f.q:
        pattern = p(f"%{_like_escape(f.q)}%")
        where.append("(" + " OR ".join(f"{c} ILIKE {pattern}" for c in _Q_COLUMNS) + ")")
    if f.cursor:
        # Keyset paging: "rows after the last one I saw". Unlike OFFSET it stays fast on deep
        # pages and doesn't skip/duplicate rows when new events arrive between page loads.
        ts, event_id = decode_cursor(f.cursor)
        where.append(f"(ts, id) < ({p(ts)}, {p(event_id)})")

    # Fetch one extra row to know whether there is a next page without a COUNT(*).
    sql = (f"SELECT * FROM events WHERE {' AND '.join(where)} "
           f"ORDER BY ts DESC, id DESC LIMIT {p(f.limit + 1)}")
    return sql, args
