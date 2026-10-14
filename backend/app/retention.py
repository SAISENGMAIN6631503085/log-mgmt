"""Retention: drop days of events older than RETENTION_DAYS.

Events live in ClickHouse, split into one partition per day (PARTITION BY toDate(ts)), so
removing a day is `ALTER TABLE ... DROP PARTITION`: instant, and the disk space is freed at once.
A `DELETE ... WHERE ts < x` would rewrite data files instead. The tables' TTL removes the same
rows too, but only when ClickHouse next merges those files; this job makes it happen on time.
New days need no preparation: ClickHouse creates a day's partition on its first insert.

Runs hourly from the backend (and on `make retention`). Every step is idempotent, so running
more often than daily is harmless, and a restart or a missed day catches up on the next run.
"""
import asyncio
import logging
import re
from datetime import date, datetime, timedelta, timezone

import asyncpg

from . import db
from .clickhouse import ch
from .config import settings

log = logging.getLogger("retention")

INTERVAL_SECONDS = 3600
_LOCK_ID = 7_340_003
# The day tables: raw events and their per-minute totals, both partitioned by day.
TABLES = ("events", "events_minutely")
# ClickHouse names a toDate() partition YYYYMMDD; only names of exactly that form are dropped.
_PARTITION_ID = re.compile(r"^(\d{8})$")


def partitions_to_drop(ids: list[str], today: date, retention_days: int) -> list[str]:
    """Pure: which partition ids (days) are older than the retention window.

    Kept: today and the previous `retention_days` days, the same range that ingest accepts.
    """
    oldest_kept = today - timedelta(days=retention_days)
    drop = []
    for pid in ids:
        m = _PARTITION_ID.match(pid)
        if not m:
            continue  # not a day partition; never touch it
        try:
            day = datetime.strptime(m.group(1), "%Y%m%d").date()
        except ValueError:
            continue
        if day < oldest_kept:
            drop.append(pid)
    return sorted(drop)


async def partition_ids() -> list[str]:
    rows = await ch.query("SELECT DISTINCT partition_id FROM system.parts "
                          "WHERE database = currentDatabase() AND table IN {tables:Array(String)} AND active",
                          {"tables": list(TABLES)})
    return [r["partition_id"] for r in rows]


async def run_retention(conn: asyncpg.Connection, now: datetime | None = None,
                        retention_days: int | None = None) -> list[str]:
    """Returns the ids (YYYYMMDD) of the days dropped."""
    now = now or datetime.now(timezone.utc)
    retention_days = settings.retention_days if retention_days is None else retention_days
    async with conn.transaction():
        # Postgres advisory lock: one retention run at a time, even with several backends.
        if not await conn.fetchval("SELECT pg_try_advisory_xact_lock($1)", _LOCK_ID):
            return []  # another process is already doing it
        # Sign-in throttling only looks back minutes; keep a day for anyone investigating.
        await conn.execute("DELETE FROM login_failures WHERE ts < $1::timestamptz - interval '1 day'", now)
        dropped = partitions_to_drop(await partition_ids(), now.date(), retention_days)
        for pid in dropped:
            for table in TABLES:
                # pid matched the strict YYYYMMDD pattern above, so it's safe in the SQL text.
                # Dropping a day a table doesn't have is a no-op.
                await ch.command(f"ALTER TABLE {table} DROP PARTITION ID '{pid}'")
    if dropped:
        log.info("retention: dropped %d day(s) older than %d days: %s",
                 len(dropped), retention_days, ", ".join(dropped))
    return dropped


async def retention_loop() -> None:
    while True:
        try:
            async with db.pool.acquire() as conn:
                await run_retention(conn)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - logged and retried next hour
            log.exception("retention run failed")
        await asyncio.sleep(INTERVAL_SECONDS)


async def _main() -> None:
    """`make retention`: run once now and print what happened."""
    await db.connect()
    try:
        async with db.pool.acquire() as conn:
            dropped = await run_retention(conn)
        days = sorted(set(await partition_ids()))
        print(f"retention: kept {settings.retention_days} days, dropped {len(dropped)} day(s)"
              f"{': ' + ', '.join(dropped) if dropped else ''}; {len(days)} days stored"
              f"{f' ({days[0]} to {days[-1]})' if days else ''}")
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(_main())
