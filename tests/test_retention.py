"""Retention: partitions older than RETENTION_DAYS are dropped, newer and future ones kept."""
import asyncio
from datetime import date, datetime, timedelta, timezone

import asyncpg
import pytest

from app.config import settings
from app.retention import partitions_to_drop, run_retention

TODAY = date(2026, 10, 12)


def name(days_ago: int) -> str:
    return f"events_{TODAY - timedelta(days=days_ago):%Y%m%d}"


# --- unit ----------------------------------------------------------------------

def test_drops_only_days_before_the_window():
    names = [name(d) for d in (30, 8, 7, 1, 0, -3)]  # -3 = future
    assert partitions_to_drop(names, TODAY, 7) == sorted([name(30), name(8)])


def test_boundary_day_is_kept():
    # Ingest accepts events up to exactly RETENTION_DAYS old, so that day's partition stays.
    assert partitions_to_drop([name(7)], TODAY, 7) == []
    assert partitions_to_drop([name(8)], TODAY, 7) == [name(8)]


@pytest.mark.parametrize("other", ["events", "events_archive", "events_2026101", "events_20261399", "users_20200101"])
def test_never_touches_tables_it_did_not_create(other):
    assert partitions_to_drop([other], TODAY, 7) == []


# --- integration -----------------------------------------------------------------

def _db(fn):
    async def run():
        c = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            return await fn(c)
        finally:
            await c.close()
    return asyncio.run(run())


def partitions() -> set[str]:
    return {r["n"] for r in _db(lambda c: c.fetch(
        "SELECT inhrelid::regclass::text AS n FROM pg_inherits WHERE inhparent = 'events'::regclass"))}


@pytest.fixture
def db_up():
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
    except (OSError, asyncpg.PostgresError, asyncio.TimeoutError):
        pytest.skip("Postgres not reachable; run `make up` first")


def test_run_retention_drops_old_partitions_with_their_rows(db_up):
    today = datetime.now(timezone.utc).date()
    keep_days = settings.retention_days
    old_days = [today - timedelta(days=keep_days + 1), today - timedelta(days=keep_days + 20)]
    edge = today - timedelta(days=keep_days)

    async def setup(c):
        for d in [*old_days, edge]:
            await c.execute("SELECT ensure_event_partition($1)", d)
            await c.execute("INSERT INTO events (ts, tenant, source, raw) VALUES ($1, 'ret_test', 'api', '{}')",
                            datetime(d.year, d.month, d.day, 12, tzinfo=timezone.utc))
    _db(setup)

    _db(run_retention)  # the backend's own hourly run may get there first; the end state is the same

    names = partitions()
    for d in old_days:
        assert f"events_{d:%Y%m%d}" not in names
    assert f"events_{edge:%Y%m%d}" in names
    assert _db(lambda c: c.fetchval("SELECT count(*) FROM events WHERE tenant = 'ret_test' AND ts < $1",
                                    datetime(edge.year, edge.month, edge.day, tzinfo=timezone.utc))) == 0
    _db(lambda c: c.execute("DELETE FROM events WHERE tenant = 'ret_test'"))


def test_run_retention_creates_partitions_ahead(db_up):
    _db(run_retention)
    today = datetime.now(timezone.utc).date()
    names = partitions()
    for ahead in range(8):
        assert f"events_{today + timedelta(days=ahead):%Y%m%d}" in names


def test_run_retention_is_idempotent(db_up):
    _db(run_retention)
    before = partitions()
    assert _db(run_retention) == []
    assert partitions() == before
