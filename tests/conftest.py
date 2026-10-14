import csv
import json
from datetime import datetime, timezone
from pathlib import Path

# Works both in the container (/app/samples is mounted next to /app/tests) and from the repo root.
SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# Fixed "current time" so syslog year inference is deterministic.
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def sample_lines(name: str) -> list[str]:
    return [l for l in (SAMPLES / name).read_text().splitlines() if l.strip()]


def sample_json(name: str):
    return json.loads((SAMPLES / name).read_text())


def sample_ndjson(name: str) -> list[dict]:
    return [json.loads(l) for l in sample_lines(name)]


def sample_csv(name: str) -> list[dict]:
    with open(SAMPLES / name, newline="") as f:
        return list(csv.DictReader(f))


def store_events(events) -> int:
    """Store Event objects through the app's own write path (events_store.insert_events), so
    they land wherever the app keeps events: Postgres and, when configured, ClickHouse.
    Tests that read events through the API seed data this way instead of raw SQL."""
    import asyncio

    import asyncpg

    from app import db as app_db
    from app.clickhouse import ch
    from app.config import settings
    from app.events_store import insert_events

    async def run():
        conn = await asyncpg.connect(settings.database_dsn, timeout=2)
        await app_db._init_connection(conn)
        if ch.enabled:
            await ch.connect()
        try:
            return await insert_events(conn, events)
        finally:
            await conn.close()
            await ch.close()
    return asyncio.run(run())


# Test tenants whose ClickHouse events are deleted once, at the end of the run (see below).
_CH_CLEANUP: set[str] = set()


def delete_events(tenants: list[str]) -> None:
    """Remove test tenants' events: from Postgres now, from ClickHouse at the end of the run.

    A ClickHouse DELETE rewrites data files in the background; one per test piled up and made
    the suite slower every run. Every test uses its own random tenant, so leftovers until the end
    can't affect other tests.
    """
    import asyncio

    import asyncpg

    from app.config import settings

    async def run():
        conn = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            await conn.execute("DELETE FROM events WHERE tenant = ANY($1)", tenants)
        finally:
            await conn.close()
    asyncio.run(run())
    _CH_CLEANUP.update(tenants)


def pytest_sessionfinish(session, exitstatus):
    """One ClickHouse delete for all test tenants, not waited for (lightweight_deletes_sync=0)."""
    if not _CH_CLEANUP:
        return
    import asyncio

    from app.clickhouse import ch

    async def run():
        try:
            for table in ("events", "events_minutely"):
                await ch.command(f"DELETE FROM {table} WHERE tenant IN {{t:Array(String)}} "
                                 "SETTINGS lightweight_deletes_sync = 0", {"t": sorted(_CH_CLEANUP)})
        finally:
            await ch.close()
    if ch.enabled:
        asyncio.run(run())
