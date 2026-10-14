"""Writing normalized events (to ClickHouse, the event store)."""
from datetime import datetime, timedelta, timezone

from . import ch_events
from .normalizers.common import Event


def check_ts_window(ts: datetime, retention_days: int, now: datetime | None = None) -> str | None:
    """Return an error if the event is outside what we can store, else None.

    Older than retention: its day would be dropped by the next retention run anyway.
    More than a day in the future: almost always a broken clock or timezone bug.
    """
    now = now or datetime.now(timezone.utc)
    if ts < now - timedelta(days=retention_days):
        return f"timestamp {ts.isoformat()} is older than the {retention_days}-day retention window"
    if ts > now + timedelta(days=1):
        return f"timestamp {ts.isoformat()} is more than 1 day in the future"
    return None


async def insert_events(events: list[Event]) -> int:
    """Store a batch in ClickHouse; returns how many were new (duplicates are skipped).

    If ClickHouse is down this raises, so the caller gets an error and retries: an HTTP sender
    or Vector (which keeps a buffer) sends the batch again later, and dedup makes that safe.
    """
    return await ch_events.insert_events(events)
