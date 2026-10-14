"""Dashboard numbers. One endpoint, several small aggregate queries, all tenant-scoped."""
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import ch_stats, db, geoip
from ..auth import Claims, current_user, require_admin, scoped_tenant
from ..clickhouse import ch
from ..config import settings
from ..normalizers.common import Source

router = APIRouter(prefix="/api", tags=["stats"])


def bucket_for(span: timedelta) -> timedelta:
    """Pick a timeline bucket so the chart has roughly 24-170 points, not 10,000."""
    if span <= timedelta(hours=6):
        return timedelta(minutes=15)
    if span <= timedelta(days=2):
        return timedelta(hours=1)
    return timedelta(days=1)


@router.get("/stats")
async def stats(
    tenant: str = Depends(scoped_tenant),
    start: datetime | None = Query(None, alias="from"),
    end: datetime | None = Query(None, alias="to"),
    source: list[Source] = Query([], description="Only these sources (repeatable); default all"),
) -> dict[str, Any]:
    end = end or datetime.now(timezone.utc)
    start = start or end - timedelta(hours=24)
    start, end = (t if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in (start, end))
    if start >= end:
        raise HTTPException(422, "`from` must be before `to`")
    bucket = bucket_for(end - start)
    async with db.pool.acquire() as conn:
        open_alerts = await conn.fetchval(
            "SELECT count(*) FROM alerts WHERE tenant = $1 AND status = 'open'", tenant)
    # Logs are summarized by ClickHouse when it's configured; alerts always live in Postgres.
    data = (await ch_stats.compute(tenant, start, end, list(source), bucket) if ch.enabled
            else await _postgres_stats(tenant, start, end, source, bucket))
    data["totals"]["open_alerts"] = open_alerts
    return {
        "tenant": tenant,
        "from": start.isoformat(),
        "to": end.isoformat(),
        "sources": source,
        "bucket_seconds": int(bucket.total_seconds()),
        **data,
    }


async def _postgres_stats(tenant: str, start: datetime, end: datetime, source: list[str], bucket: timedelta) -> dict[str, Any]:
    """The same numbers from the Postgres events table (used until ClickHouse is configured)."""
    began = time.perf_counter()
    # $1 tenant, $2 from, $3 to, $4 sources (NULL = all) in every events query below.
    scope = (tenant, start, end, source or None)

    async with db.pool.acquire() as conn:
        totals = await conn.fetchrow(
            """SELECT count(*) AS events,
                      count(*) FILTER (WHERE _tags @> '{auth_failure}') AS auth_failures,
                      count(*) FILTER (WHERE severity >= 7) AS high_severity,
                      count(DISTINCT src_ip) AS unique_src_ips
               FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND ($4::text[] IS NULL OR source = ANY($4))""", *scope)
        # generate_series + LEFT JOIN: empty buckets show as 0 instead of disappearing,
        # so a quiet hour looks quiet on the chart rather than being skipped.
        # Each bucket is split by severity band (for the stacked chart) and also counts
        # failed logins / high severity (for the KPI sparklines).
        timeline = await conn.fetch(
            """WITH buckets AS (
                   SELECT generate_series(date_bin($5::interval, $2, 'epoch'), $3, $5::interval) AS t),
               agg AS (
                   SELECT date_bin($5::interval, ts, 'epoch') AS t,
                          count(*) AS n,
                          count(*) FILTER (WHERE severity >= 9) AS critical,
                          count(*) FILTER (WHERE severity BETWEEN 7 AND 8) AS high,
                          count(*) FILTER (WHERE severity BETWEEN 4 AND 6) AS medium,
                          count(*) FILTER (WHERE severity <= 3) AS low,
                          count(*) FILTER (WHERE severity IS NULL) AS unknown,
                          count(*) FILTER (WHERE _tags @> '{auth_failure}') AS auth_failures
                   FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND ($4::text[] IS NULL OR source = ANY($4))
                   GROUP BY 1)
               SELECT b.t, coalesce(a.n, 0) AS n, coalesce(a.critical, 0) AS critical,
                      coalesce(a.high, 0) AS high, coalesce(a.medium, 0) AS medium,
                      coalesce(a.low, 0) AS low, coalesce(a.unknown, 0) AS unknown,
                      coalesce(a.auth_failures, 0) AS auth_failures
               FROM buckets b LEFT JOIN agg a USING (t) ORDER BY b.t""", *scope, bucket)
        # The same-length window just before this one, for "vs previous period" on the KPIs.
        previous = await conn.fetchrow(
            """SELECT count(*) AS events,
                      count(*) FILTER (WHERE _tags @> '{auth_failure}') AS auth_failures,
                      count(*) FILTER (WHERE severity >= 7) AS high_severity
               FROM events WHERE tenant = $1 AND ts >= $2::timestamptz - ($3::timestamptz - $2::timestamptz)
                 AND ts < $2::timestamptz AND ($4::text[] IS NULL OR source = ANY($4))""", *scope)
        # Source x time bucket counts for the activity heatmap (only non-empty cells).
        source_timeline = await conn.fetch(
            """SELECT source, date_bin($5::interval, ts, 'epoch') AS t, count(*) AS n
               FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND ($4::text[] IS NULL OR source = ANY($4))
               GROUP BY 1, 2""", *scope, bucket)
        by_source = await conn.fetch(
            """SELECT source AS key, count(*) AS n FROM events
               WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND ($4::text[] IS NULL OR source = ANY($4))
               GROUP BY source ORDER BY n DESC""", *scope)
        by_severity = await conn.fetch(
            """SELECT CASE WHEN severity >= 9 THEN 'critical' WHEN severity >= 7 THEN 'high'
                           WHEN severity >= 4 THEN 'medium' WHEN severity IS NOT NULL THEN 'low'
                           ELSE 'unknown' END AS key, count(*) AS n
               FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND ($4::text[] IS NULL OR source = ANY($4)) GROUP BY 1""", *scope)
        top_src_ips = await conn.fetch(
            """SELECT host(src_ip) AS key, count(*) AS n, max(src_country) AS country,
                      count(*) FILTER (WHERE _tags @> '{auth_failure}') AS auth_failures
               FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND ($4::text[] IS NULL OR source = ANY($4)) AND src_ip IS NOT NULL
               GROUP BY src_ip ORDER BY n DESC LIMIT 10""", *scope)
        top_users = await conn.fetch(
            """SELECT username AS key, count(*) AS n,
                      count(*) FILTER (WHERE _tags @> '{auth_failure}') AS auth_failures
               FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND ($4::text[] IS NULL OR source = ANY($4))
                 AND username IS NOT NULL
               GROUP BY username ORDER BY n DESC LIMIT 10""", *scope)
        top_countries = await conn.fetch(
            """SELECT src_country AS key, count(*) AS n,
                      count(*) FILTER (WHERE _tags @> '{auth_failure}') AS auth_failures
               FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND ($4::text[] IS NULL OR source = ANY($4))
                 AND src_country IS NOT NULL
               GROUP BY src_country ORDER BY n DESC LIMIT 10""", *scope)
        top_event_types = await conn.fetch(
            """SELECT event_type AS key, count(*) AS n FROM events
               WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND ($4::text[] IS NULL OR source = ANY($4))
                 AND event_type IS NOT NULL
               GROUP BY event_type ORDER BY n DESC LIMIT 10""", *scope)

    severity_order = ["critical", "high", "medium", "low", "unknown"]
    sev = {r["key"]: r["n"] for r in by_severity}
    return {
        "totals": dict(totals),
        "previous": dict(previous),
        "timeline": [dict(r) | {"t": r["t"].isoformat()} for r in timeline],
        "source_timeline": [{"source": r["source"], "t": r["t"].isoformat(), "n": r["n"]} for r in source_timeline],
        "by_source": [dict(r) for r in by_source],
        # Fixed order (severity is ordinal), zeros included so the chart shape is stable.
        "by_severity": [{"key": k, "n": sev.get(k, 0)} for k in severity_order],
        "top_src_ips": [dict(r) for r in top_src_ips],
        "top_users": [dict(r) for r in top_users],
        "top_countries": [dict(r) for r in top_countries],
        "top_event_types": [dict(r) for r in top_event_types],
        "engine": {"name": "postgres", "ms": round((time.perf_counter() - began) * 1000)},
    }


@router.get("/info")
async def info(_: Claims = Depends(current_user)) -> dict[str, Any]:
    """What the website needs to label things honestly: is the data generated by the demo
    simulator, and is country lookup available."""
    return {"demo_data": settings.demo_data, "geoip": geoip.enabled()}


@router.get("/tenants")
async def tenants(_: Claims = Depends(require_admin)) -> list[str]:
    """For the admin's tenant switcher: every tenant that has users or ingest keys."""
    async with db.pool.acquire() as conn:
        rows = await conn.fetch("SELECT tenant FROM users UNION SELECT tenant FROM api_keys ORDER BY 1")
    return [r["tenant"] for r in rows]
