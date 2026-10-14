"""Writing normalized events to ClickHouse.

Duplicates: ClickHouse has no unique constraint. ReplacingMergeTree removes exact repeats when it
merges parts (eventually), so we also skip events whose fingerprint is already stored before
inserting. That keeps counts right straight away and lets ingest report "duplicates" like before.
"""
import hashlib
import itertools
import json
import secrets
import time

from .clickhouse import _param, ch
from .normalizers.common import Event

CHECK_CHUNK = 300  # fingerprints per duplicate-check query (~20 KB of URL)


def fingerprint(e: Event) -> str:
    """sha256 of tenant + source + original payload, with keys sorted so equal JSON hashes equal."""
    text = json.dumps([e.tenant, e.source, e.raw], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode()).hexdigest()


# Low 22 bits: a counter, not random bits. Random bits collide surprisingly often when one upload
# makes thousands of ids in the same millisecond (birthday problem); a counter can't repeat until
# 4 million ids. It starts at a random point so separate backend processes are unlikely to overlap.
_seq = itertools.count(secrets.randbits(22))


def new_id() -> int:
    """Time-ordered 63-bit id: milliseconds since 1970 in the high bits, a counter below.
    Sorts roughly by arrival, like Postgres' identity column, without a central sequence."""
    return (int(time.time() * 1000) << 22) | (next(_seq) & 0x3FFFFF)


def _row(e: Event, fp: str) -> dict:
    d = e.model_dump(exclude={"raw", "tags", "user"})
    d.update(id=new_id(), ts=e.ts.isoformat(), username=e.user, raw=json.dumps(e.raw, default=str),
             tags=e.tags, fingerprint=fp)
    return d


async def insert_events(events: list[Event]) -> int:
    """Store the batch; returns how many were new.

    A duplicate is the same fingerprint at the same time, exactly like Postgres' unique
    (fingerprint, ts): the same log content at a different time (e.g. an old sample re-sent and
    stored at its arrival time) is a new event. It's also the table's ORDER BY key, so
    ReplacingMergeTree agrees when it merges.
    """
    if not events:
        return 0
    batch: dict[tuple[str, str], Event] = {}
    for e in events:
        batch.setdefault((fingerprint(e), _param(e.ts)), e)  # repeats inside one batch count once
    tenants = sorted({e.tenant for e in batch.values()})
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
    rows = [_row(e, fp) for (fp, ts), e in batch.items() if (fp, ts) not in seen]
    await ch.insert("events", rows)
    return len(rows)
