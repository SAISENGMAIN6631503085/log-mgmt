"""Writing normalized events to Postgres."""
import ipaddress
from datetime import datetime, timedelta, timezone

import asyncpg

from .normalizers.common import Event

# Column order for COPY. `user` -> username and `tags` -> _tags (see migration 001).
_COLUMNS = [
    "ts", "tenant", "source", "vendor", "product", "event_type", "event_subtype", "severity",
    "action", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "username", "host",
    "process", "url", "http_method", "status_code", "rule_name", "rule_id",
    "cloud_account_id", "cloud_region", "cloud_service", "raw", "_tags",
]


def check_ts_window(ts: datetime, retention_days: int, now: datetime | None = None) -> str | None:
    """Return an error if the event is outside what we can store, else None.

    Older than retention: its partition would be dropped by the next retention run anyway.
    More than a day in the future: almost always a broken clock or timezone bug, and it
    would need partitions we don't create ahead of time.
    """
    now = now or datetime.now(timezone.utc)
    if ts < now - timedelta(days=retention_days):
        return f"timestamp {ts.isoformat()} is older than the {retention_days}-day retention window"
    if ts > now + timedelta(days=1):
        return f"timestamp {ts.isoformat()} is more than 1 day in the future"
    return None


def _row(e: Event) -> tuple:
    ip = lambda v: ipaddress.ip_address(v) if v else None  # noqa: E731 - asyncpg's inet codec wants ip objects
    return (
        e.ts, e.tenant, e.source, e.vendor, e.product, e.event_type, e.event_subtype, e.severity,
        e.action, ip(e.src_ip), e.src_port, ip(e.dst_ip), e.dst_port, e.protocol, e.user, e.host,
        e.process, e.url, e.http_method, e.status_code, e.rule_name, e.rule_id,
        e.cloud_account_id, e.cloud_region, e.cloud_service, e.raw, e.tags,
    )


async def insert_events(conn: asyncpg.Connection, events: list[Event]) -> int:
    """Insert a batch in one transaction using COPY (much faster than row-by-row INSERTs)."""
    if not events:
        return 0
    async with conn.transaction():
        # Back-dated events may belong to a day whose partition doesn't exist yet.
        for day in sorted({e.ts.date() for e in events}):
            await conn.execute("SELECT ensure_event_partition($1)", day)
        await conn.copy_records_to_table("events", records=[_row(e) for e in events], columns=_COLUMNS)
    return len(events)
