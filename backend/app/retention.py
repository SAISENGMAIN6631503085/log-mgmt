"""Retention: drop event partitions older than RETENTION_DAYS and pre-create upcoming ones.

Dropping a whole day's partition is instant and frees disk at once. A `DELETE ... WHERE ts < x`
on a big table would be slow, lock-heavy and leave dead rows for VACUUM.

Runs hourly from the backend (and on `make retention`). Every step is idempotent, so running
more often than daily is harmless, and a restart or a missed day catches up on the next run.
"""
import asyncio
import logging
import re
from datetime import date, datetime, timedelta, timezone

import asyncpg

from . import db
from .config import settings
from .migrate import ensure_partitions

log = logging.getLogger("retention")

INTERVAL_SECONDS = 3600
_LOCK_ID = 7_340_003
# Only tables named exactly like ensure_event_partition() names them are ever dropped.
_PARTITION_NAME = re.compile(r"^events_(\d{8})$")


def partitions_to_drop(names: list[str], today: date, retention_days: int) -> list[str]:
    """Pure: which partition names are older than the retention window.

    Kept: today and the previous `retention_days` days, i.e. the same range that
    ensure_partitions() creates and that ingest accepts.
    """
    oldest_kept = today - timedelta(days=retention_days)
    drop = []
    for name in names:
        m = _PARTITION_NAME.match(name)
        if not m:
            continue  # not ours; never touch it
        try:
            day = datetime.strptime(m.group(1), "%Y%m%d").date()
        except ValueError:
            continue
        if day < oldest_kept:
            drop.append(name)
    return sorted(drop)


async def run_retention(conn: asyncpg.Connection, now: datetime | None = None,
                        retention_days: int | None = None) -> list[str]:
    """Returns the names of dropped partitions."""
    now = now or datetime.now(timezone.utc)
    retention_days = settings.retention_days if retention_days is None else retention_days
    async with conn.transaction():
        if not await conn.fetchval("SELECT pg_try_advisory_xact_lock($1)", _LOCK_ID):
            return []  # another process is already doing it
        await ensure_partitions(conn, retention_days)
        names = [r["name"] for r in await conn.fetch(
            "SELECT inhrelid::regclass::text AS name FROM pg_inherits WHERE inhparent = 'events'::regclass")]
        dropped = partitions_to_drop(names, now.date(), retention_days)
        for name in dropped:
            # Name comes from the catalog and matched the strict regex above; quote_ident anyway.
            await conn.execute(f"DROP TABLE {await conn.fetchval('SELECT quote_ident($1)', name)}")
    if dropped:
        log.info("retention: dropped %d partition(s) older than %d days: %s",
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
            count = await conn.fetchval("SELECT count(*) FROM pg_inherits WHERE inhparent = 'events'::regclass")
        print(f"retention: kept {settings.retention_days} days, dropped {len(dropped)} partition(s)"
              f"{': ' + ', '.join(dropped) if dropped else ''}; {count} partitions now")
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(_main())
