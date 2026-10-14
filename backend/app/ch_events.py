"""Writing normalized events to ClickHouse.

Duplicates: ClickHouse has no unique constraint. ReplacingMergeTree removes exact repeats when it
merges parts (eventually), so we also skip events whose fingerprint is already stored before
inserting. That keeps counts right straight away and lets ingest report "duplicates" like before.
"""
import hashlib
import json
import secrets
import time
from datetime import datetime

from .clickhouse import _param, ch
from .normalizers.common import Event

CHECK_CHUNK = 300  # fingerprints per duplicate-check query (~20 KB of URL)


def fingerprint(e: Event) -> str:
    """sha256 of tenant + source + original payload, with keys sorted so equal JSON hashes equal."""
    text = json.dumps([e.tenant, e.source, e.raw], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode()).hexdigest()


# Ids must fit in 53 bits: browsers keep JSON numbers as doubles, which are exact only up to
# 2^53, so a bigger id could come back changed and open the wrong event. Layout: milliseconds
# since 1970 (41 bits, good until 2039) shifted left by 12, plus a counter. The id only ever goes
# up, even for a 10,000-event batch inside one millisecond: it then runs slightly ahead of the
# clock. Each process adds its own random offset to the millisecond, so two processes (the API
# and a backfill, say) starting in the same millisecond are unlikely to hand out the same id.
_OFFSET = secrets.randbits(11)
_last_id = 0


def new_id() -> int:
    """Unique (per process), increasing, roughly time-ordered, and exact in JavaScript."""
    global _last_id
    _last_id = max(_last_id + 1, (int(time.time() * 1000) << 12) + _OFFSET)
    return _last_id


def _row(e: Event, fp: str, ingested_at: datetime | None) -> dict:
    d = e.model_dump(exclude={"raw", "tags", "user"})
    d.update(id=new_id(), ts=e.ts.isoformat(), username=e.user, raw=json.dumps(e.raw, default=str),
             tags=e.tags, fingerprint=fp)
    if ingested_at is not None:
        d["ingested_at"] = ingested_at.isoformat()
    return d


async def insert_events(events: list[Event], ingested_at: list[datetime] | None = None) -> int:
    """Store the batch; returns how many were new.

    `ingested_at` (one per event) keeps each event's original arrival time when copying old
    events; otherwise it's now. It matters: the alert worker re-checks events that arrived
    recently, so copied events stamped "now" would be treated as new and alert again.

    A duplicate is the same fingerprint at the same time, exactly like Postgres' unique
    (fingerprint, ts): the same log content at a different time (e.g. an old sample re-sent and
    stored at its arrival time) is a new event. It's also the table's ORDER BY key, so
    ReplacingMergeTree agrees when it merges.
    """
    if not events:
        return 0
    arrived = ingested_at or [None] * len(events)
    batch: dict[tuple[str, str], tuple[Event, datetime | None]] = {}
    for e, at in zip(events, arrived, strict=True):
        batch.setdefault((fingerprint(e), _param(e.ts)), (e, at))  # repeats inside one batch count once
    tenants = sorted({e.tenant for e, _ in batch.values()})
    fps = sorted({fp for fp, _ in batch})
    seen: set[tuple[str, str]] = set()
    # Parameters travel in the URL, so check in chunks: thousands of 64-character fingerprints
    # in one request would exceed the URL length limit.
    for i in range(0, len(fps), CHECK_CHUNK):
        rows = await ch.query(
            "SELECT DISTINCT fingerprint, toString(ts) AS ts FROM events "
            "WHERE tenant IN {tenants:Array(String)} AND fingerprint IN {fps:Array(String)}",
            {"tenants": tenants, "fps": fps[i:i + CHECK_CHUNK]})
        seen.update((r["fingerprint"], r["ts"]) for r in rows)
    rows = [_row(e, fp, at) for (fp, ts), (e, at) in batch.items() if (fp, ts) not in seen]
    await ch.insert("events", rows)
    return len(rows)
