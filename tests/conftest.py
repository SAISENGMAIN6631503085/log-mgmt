"""Shared test helpers. Integration tests use the real databases and the Go ingest service
(run them with `make test`); each test uses its own random tenant."""
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# The Go ingest service, reached on the compose network (tests run in a container there).
INGEST_URL = os.environ.get("INGEST_URL", "http://ingest:8080")


def ingest_client():
    """HTTP client for the ingest service: logs are sent to it, as Caddy and Vector do."""
    import httpx
    return httpx.Client(base_url=INGEST_URL, timeout=30)


@dataclass
class Event:
    """A normalized event, for seeding test data (normalizing is the Go service's job).
    Field names follow the common schema."""
    ts: datetime
    tenant: str
    source: str
    raw: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)
    vendor: str | None = None
    product: str | None = None
    event_type: str | None = None
    event_subtype: str | None = None
    severity: int | None = None
    action: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    user: str | None = None
    host: str | None = None
    process: str | None = None
    url: str | None = None
    http_method: str | None = None
    status_code: int | None = None
    rule_name: str | None = None
    rule_id: str | None = None
    cloud_account_id: str | None = None
    cloud_region: str | None = None
    cloud_service: str | None = None
    src_country: str | None = None


def fingerprint(tenant: str, source: str, raw) -> str:
    """The dedup fingerprint, computed exactly as the Go service does (ingest/store): sha256 of
    [tenant, source, raw] as JSON with sorted keys and no spaces."""
    text = json.dumps([tenant, source, raw], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


_last_id = 0


def new_id() -> int:
    """Time-ordered ids under 2^53, the same layout the Go service uses (ms << 12 + counter),
    with a different offset so test rows never collide with real ones."""
    global _last_id
    _last_id = max(_last_id + 1, (int(time.time() * 1000) << 12) + 2047)
    return _last_id


def store_events(events: list[Event]) -> int:
    """Write test events straight into ClickHouse, for tests of what reads them (search, the
    dashboard, alerts). Tests of ingest itself send logs to the Go service instead."""
    import asyncio

    from app.clickhouse import ch

    rows = []
    for e in events:
        d = asdict(e)
        d.update(id=new_id(), ts=e.ts.isoformat(), username=d.pop("user"), raw=json.dumps(e.raw),
                 fingerprint=fingerprint(e.tenant, e.source, e.raw))
        rows.append(d)

    async def run():
        try:
            await ch.insert("events", rows)
        finally:
            await ch.close()
    asyncio.run(run())
    return len(rows)


def count_events(tenant: str, **where) -> int:
    """How many distinct events a tenant has in ClickHouse, optionally with column = value
    filters. FINAL applies ReplacingMergeTree's dedup even before ClickHouse has merged."""
    import asyncio

    from app.clickhouse import ch

    clause = "".join(f" AND {col} = {{{col}:String}}" for col in where)  # names come from the test code

    async def run():
        try:
            rows = await ch.query(f"SELECT count() AS n FROM events FINAL WHERE tenant = {{tenant:String}}{clause}",
                                  {"tenant": tenant, **where})
            return rows[0]["n"]
        finally:
            await ch.close()
    return asyncio.run(run())


# Test tenants whose events are deleted once, at the end of the run (see below), and device
# names (`host`) of test events that had to go to a real tenant (syslog's DEFAULT_TENANT).
_CH_CLEANUP: set[str] = set()
_CH_CLEANUP_HOSTS: set[str] = set()


def delete_events(tenants: list[str]) -> None:
    """Mark test tenants' events for deletion at the end of the run.

    A ClickHouse DELETE rewrites data files in the background; one per test piled up and made
    the suite slower every run. Every test uses its own random tenant, so leftovers until the end
    can't affect other tests.
    """
    _CH_CLEANUP.update(tenants)


def pytest_sessionfinish(session, exitstatus):
    """One ClickHouse delete for all test tenants, not waited for (lightweight_deletes_sync=0)."""
    if not (_CH_CLEANUP or _CH_CLEANUP_HOSTS):
        return
    import asyncio

    from app.clickhouse import ch

    async def run():
        try:
            for table in ("events", "events_minutely"):
                await ch.command(f"DELETE FROM {table} WHERE tenant IN {{t:Array(String)}} "
                                 "SETTINGS lightweight_deletes_sync = 0", {"t": sorted(_CH_CLEANUP)})
            # events_minutely has no host column; a test event or two in a real tenant's totals is harmless.
            await ch.command("DELETE FROM events WHERE host IN {h:Array(String)} "
                             "SETTINGS lightweight_deletes_sync = 0", {"h": sorted(_CH_CLEANUP_HOSTS)})
        finally:
            await ch.close()
    asyncio.run(run())
