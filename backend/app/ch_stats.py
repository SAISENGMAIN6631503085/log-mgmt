"""Dashboard numbers from ClickHouse, for /api/stats (routers/stats.py).

- Counts, timeline and breakdowns read `events_minutely`, the ready-made per-minute totals kept by
  a materialized view, so they cost the same whether there are a thousand logs or a billion.
  Precision is one minute, which a dashboard can't show anyway.
- Top lists (IPs, users, countries, event types) need the individual values, so they read the
  `events` table; it's sorted by (tenant, ts), so only this tenant's time range is scanned.

Every value is a typed parameter ({tenant:String} ...), never pasted into the SQL.
"""
import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .clickhouse import ch

# Shared filters: this tenant, this time range, optionally these sources (empty list = all).
_MIN_WHERE = ("tenant = {tenant:String} AND minute >= toStartOfMinute({start:DateTime64(3, 'UTC')}) "
              "AND minute < {end:DateTime64(3, 'UTC')} AND (empty({sources:Array(String)}) OR source IN {sources:Array(String)})")
_RAW_WHERE = ("tenant = {tenant:String} AND ts >= {start:DateTime64(3, 'UTC')} AND ts < {end:DateTime64(3, 'UTC')} "
              "AND (empty({sources:Array(String)}) OR source IN {sources:Array(String)})")

_SEVERITY = ["critical", "high", "medium", "low", "unknown"]


def _top(column: str, extra: str = "") -> str:
    return (f"SELECT {column} AS key, count() AS n, countIf(has(tags, 'auth_failure')) AS auth_failures{extra} "
            f"FROM events WHERE {_RAW_WHERE} AND {column} IS NOT NULL GROUP BY key ORDER BY n DESC, key LIMIT 10")


def _buckets(start: datetime, end: datetime, bucket: timedelta) -> list[int]:
    """Bucket starts (epoch seconds) from the one containing `start` up to `end`, so empty
    periods show as 0 instead of disappearing."""
    step = int(bucket.total_seconds())
    t = int(start.timestamp()) // step * step
    out = []
    while t <= end.timestamp():
        out.append(t)
        t += step
    return out


async def compute(tenant: str, start: datetime, end: datetime, sources: list[str], bucket: timedelta) -> dict[str, Any]:
    p = {"tenant": tenant, "start": start, "end": end, "sources": sources}
    prev = {**p, "start": start - (end - start), "end": start}
    step = int(bucket.total_seconds())
    began = time.perf_counter()

    totals_sql = (f"SELECT sum(n) AS events, sum(auth_failures) AS auth_failures, "
                  f"sum(critical) + sum(high) AS high_severity FROM events_minutely WHERE {_MIN_WHERE}")
    queries = [
        ch.query(totals_sql, p),
        ch.query(totals_sql, prev),
        ch.query(f"SELECT uniqExact(src_ip) AS u FROM events WHERE {_RAW_WHERE} AND src_ip IS NOT NULL", p),
        ch.query("SELECT intDiv(toUnixTimestamp(minute), {step:UInt32}) * {step:UInt32} AS t, "
                 "sum(n) AS n, sum(critical) AS critical, sum(high) AS high, sum(medium) AS medium, "
                 "sum(low) AS low, sum(unknown) AS unknown, sum(auth_failures) AS auth_failures "
                 f"FROM events_minutely WHERE {_MIN_WHERE} GROUP BY t", {**p, "step": step}),
        ch.query("SELECT source, intDiv(toUnixTimestamp(minute), {step:UInt32}) * {step:UInt32} AS t, sum(n) AS n "
                 f"FROM events_minutely WHERE {_MIN_WHERE} GROUP BY source, t HAVING n > 0 ORDER BY source, t", {**p, "step": step}),
        ch.query(f"SELECT source AS key, sum(n) AS n FROM events_minutely WHERE {_MIN_WHERE} "
                 "GROUP BY key HAVING n > 0 ORDER BY n DESC, key", p),
        ch.query("SELECT sum(critical) AS critical, sum(high) AS high, sum(medium) AS medium, "
                 f"sum(low) AS low, sum(unknown) AS unknown FROM events_minutely WHERE {_MIN_WHERE}", p),
        ch.query(_top("src_ip", ", anyIf(src_country, src_country IS NOT NULL) AS country"), p),
        ch.query(_top("username"), p),
        ch.query(_top("src_country"), p),
        ch.query(f"SELECT event_type AS key, count() AS n FROM events WHERE {_RAW_WHERE} AND event_type IS NOT NULL "
                 "GROUP BY key ORDER BY n DESC, key LIMIT 10", p),
    ]
    (totals, previous, unique_ips, timeline, source_timeline, by_source, by_severity,
     top_ips, top_users, top_countries, top_types) = await asyncio.gather(*queries)

    by_bucket = {r["t"]: r for r in timeline}
    zero = {k: 0 for k in ["n", *_SEVERITY, "auth_failures"]}
    iso = lambda t: datetime.fromtimestamp(t, tz=timezone.utc).isoformat()  # noqa: E731
    sev = by_severity[0] if by_severity else {}
    return {
        "totals": {**totals[0], "unique_src_ips": unique_ips[0]["u"]},
        "previous": previous[0],
        "timeline": [{"t": iso(t), **{k: by_bucket.get(t, zero)[k] for k in zero}} for t in _buckets(start, end, bucket)],
        "source_timeline": [{"source": r["source"], "t": iso(r["t"]), "n": r["n"]} for r in source_timeline],
        "by_source": by_source,
        "by_severity": [{"key": k, "n": sev.get(k, 0)} for k in _SEVERITY],
        "top_src_ips": top_ips,
        "top_users": top_users,
        "top_countries": top_countries,
        "top_event_types": top_types,
        "engine": {"name": "clickhouse", "ms": round((time.perf_counter() - began) * 1000)},
    }
