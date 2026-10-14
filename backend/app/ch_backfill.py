"""`make ch-backfill`: copy events already stored in Postgres into ClickHouse.

Needed once when ClickHouse is added to an existing install. Safe to run again: events whose
fingerprint is already in ClickHouse are skipped.

`make ch-rebuild` (--rebuild) first empties ClickHouse's events and per-minute totals, then copies
everything again. Only for while Postgres still holds every event (the migration phases).
"""
import asyncio
import sys

from . import ch_events, db
from .clickhouse import ch
from .normalizers.common import Event

BATCH = 2000

_FIELDS = [f for f in Event.model_fields if f not in ("user", "tags")]


def _event(r) -> Event:
    d = {k: r[k] for k in _FIELDS if k in r.keys()}
    d["user"] = r["username"]
    d["tags"] = list(r["_tags"])
    for k in ("src_ip", "dst_ip"):
        d[k] = str(d[k]) if d.get(k) is not None else None
    return Event(**d)


async def main() -> None:
    await db.connect()
    if not ch.enabled:
        print("ClickHouse is not configured (CLICKHOUSE_URL is empty); nothing to do")
        return
    copied = seen = 0
    last = (None, 0)
    if "--rebuild" in sys.argv:
        for table in ("events_minutely", "events"):
            await ch.command(f"TRUNCATE TABLE {table}")
        print("ch-rebuild: emptied events and events_minutely")
    try:
        async with db.pool.acquire() as conn:
            while True:
                # Keyset paging by (ts, id): steady speed however many rows there are.
                rows = await conn.fetch(
                    """SELECT * FROM events WHERE ($1::timestamptz IS NULL OR (ts, id) > ($1, $2))
                       ORDER BY ts, id LIMIT $3""", last[0], last[1], BATCH)
                if not rows:
                    break
                seen += len(rows)
                copied += await ch_events.insert_events([_event(r) for r in rows])
                last = (rows[-1]["ts"], rows[-1]["id"])
    finally:
        await db.disconnect()
    print(f"ch-backfill: {seen} events read from Postgres, {copied} copied, {seen - copied} already there")


if __name__ == "__main__":
    asyncio.run(main())
