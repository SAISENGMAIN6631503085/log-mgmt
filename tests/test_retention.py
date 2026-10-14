"""Retention: days (ClickHouse partitions) older than RETENTION_DAYS are dropped, newer and future ones kept."""
import asyncio
from datetime import date, datetime, timedelta, timezone

import asyncpg
import pytest

from app import ch_events
from app.clickhouse import ch
from app.config import settings
from app.retention import partition_ids, partitions_to_drop, run_retention
from conftest import _CH_CLEANUP

TODAY = date(2026, 10, 12)


def name(days_ago: int) -> str:
    """ClickHouse's partition id for that day (PARTITION BY toDate(ts))."""
    return f"{TODAY - timedelta(days=days_ago):%Y%m%d}"


# --- unit ----------------------------------------------------------------------

def test_drops_only_days_before_the_window():
    names = [name(d) for d in (30, 8, 7, 1, 0, -3)]  # -3 = future
    assert partitions_to_drop(names, TODAY, 7) == sorted([name(30), name(8)])


def test_boundary_day_is_kept():
    # Ingest accepts events up to exactly RETENTION_DAYS old, so that day stays.
    assert partitions_to_drop([name(7)], TODAY, 7) == []
    assert partitions_to_drop([name(8)], TODAY, 7) == [name(8)]


@pytest.mark.parametrize("other", ["all", "tuple()", "2026101", "20261399", "202010-01", "users_20200101"])
def test_never_touches_partitions_that_are_not_days(other):
    assert partitions_to_drop([other], TODAY, 7) == []


# --- integration -----------------------------------------------------------------

def _db(fn):
    async def run():
        c = await asyncpg.connect(settings.database_dsn, timeout=2)
        try:
            return await fn(c)
        finally:
            await c.close()
            await ch.close()
    return asyncio.run(run())


def _ch(fn):
    async def run():
        try:
            return await fn()
        finally:
            await ch.close()
    return asyncio.run(run())


def days() -> set[str]:
    return set(_ch(partition_ids))


@pytest.fixture
def db_up():
    try:
        _db(lambda c: c.fetchval("SELECT 1"))
        _ch(lambda: ch.query("SELECT 1 AS ok"))
    except Exception:  # noqa: BLE001
        pytest.skip("databases not reachable; run `make up` first")


def test_run_retention_drops_old_days_with_their_rows(db_up):
    today = datetime.now(timezone.utc).date()
    keep_days = settings.retention_days
    old_days = [today - timedelta(days=keep_days + 1), today - timedelta(days=keep_days + 20)]
    edge = today - timedelta(days=keep_days)
    # Written straight to the table: ingest itself would refuse events this old. The edge row is
    # at 23:59 so the table's own TTL (ts + RETENTION_DAYS) can't expire it during the test.
    rows = [{"id": ch_events.new_id(), "ts": datetime(d.year, d.month, d.day, 23, 59, tzinfo=timezone.utc).isoformat(),
             "tenant": "ret_test", "source": "api", "raw": "{}", "tags": [], "fingerprint": f"ret{d}"}
            for d in [*old_days, edge]]
    _ch(lambda: ch.insert("events", rows))

    _db(run_retention)  # the backend's own hourly run may get there first; the end state is the same

    stored = days()
    for d in old_days:
        assert f"{d:%Y%m%d}" not in stored
    assert f"{edge:%Y%m%d}" in stored
    left = _ch(lambda: ch.query("SELECT count() AS n FROM events WHERE tenant = 'ret_test' AND ts < {e:DateTime64(3, 'UTC')}",
                                {"e": datetime(edge.year, edge.month, edge.day, tzinfo=timezone.utc)}))
    assert left[0]["n"] == 0
    _CH_CLEANUP.add("ret_test")


def test_run_retention_is_idempotent(db_up):
    _db(run_retention)
    before = days()
    assert _db(run_retention) == []
    assert days() == before
