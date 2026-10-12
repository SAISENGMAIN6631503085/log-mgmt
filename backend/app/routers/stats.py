"""Dashboard numbers. One endpoint, several small aggregate queries, all tenant-scoped."""
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import db
from ..auth import Claims, require_admin, scoped_tenant

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
) -> dict[str, Any]:
    end = end or datetime.now(timezone.utc)
    start = start or end - timedelta(hours=24)
    start, end = (t if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in (start, end))
    if start >= end:
        raise HTTPException(422, "`from` must be before `to`")
    bucket = bucket_for(end - start)
    scope = (tenant, start, end)  # $1, $2, $3 in every query below

    async with db.pool.acquire() as conn:
        totals = await conn.fetchrow(
            """SELECT count(*) AS events,
                      count(*) FILTER (WHERE _tags @> '{auth_failure}') AS auth_failures,
                      count(*) FILTER (WHERE severity >= 7) AS high_severity,
                      count(DISTINCT src_ip) AS unique_src_ips
               FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3""", *scope)
        open_alerts = await conn.fetchval(
            "SELECT count(*) FROM alerts WHERE tenant = $1 AND status = 'open'", tenant)
        # generate_series + LEFT JOIN: empty buckets show as 0 instead of disappearing,
        # so a quiet hour looks quiet on the chart rather than being skipped.
        timeline = await conn.fetch(
            """WITH buckets AS (
                   SELECT generate_series(date_bin($4::interval, $2, 'epoch'), $3, $4::interval) AS t)
               SELECT b.t, count(e.id) AS n
               FROM buckets b
               LEFT JOIN events e ON e.tenant = $1 AND e.ts >= $2 AND e.ts < $3
                                 AND date_bin($4::interval, e.ts, 'epoch') = b.t
               GROUP BY b.t ORDER BY b.t""", *scope, bucket)
        by_source = await conn.fetch(
            """SELECT source AS key, count(*) AS n FROM events
               WHERE tenant = $1 AND ts >= $2 AND ts < $3 GROUP BY source ORDER BY n DESC""", *scope)
        by_severity = await conn.fetch(
            """SELECT CASE WHEN severity >= 9 THEN 'critical' WHEN severity >= 7 THEN 'high'
                           WHEN severity >= 4 THEN 'medium' WHEN severity IS NOT NULL THEN 'low'
                           ELSE 'unknown' END AS key, count(*) AS n
               FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3 GROUP BY 1""", *scope)
        top_src_ips = await conn.fetch(
            """SELECT host(src_ip) AS key, count(*) AS n,
                      count(*) FILTER (WHERE _tags @> '{auth_failure}') AS auth_failures
               FROM events WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND src_ip IS NOT NULL
               GROUP BY src_ip ORDER BY n DESC LIMIT 10""", *scope)
        top_event_types = await conn.fetch(
            """SELECT event_type AS key, count(*) AS n FROM events
               WHERE tenant = $1 AND ts >= $2 AND ts < $3 AND event_type IS NOT NULL
               GROUP BY event_type ORDER BY n DESC LIMIT 10""", *scope)

    severity_order = ["critical", "high", "medium", "low", "unknown"]
    sev = {r["key"]: r["n"] for r in by_severity}
    return {
        "tenant": tenant,
        "from": start.isoformat(),
        "to": end.isoformat(),
        "bucket_seconds": int(bucket.total_seconds()),
        "totals": dict(totals) | {"open_alerts": open_alerts},
        "timeline": [{"t": r["t"].isoformat(), "n": r["n"]} for r in timeline],
        "by_source": [dict(r) for r in by_source],
        # Fixed order (severity is ordinal), zeros included so the chart shape is stable.
        "by_severity": [{"key": k, "n": sev.get(k, 0)} for k in severity_order],
        "top_src_ips": [dict(r) for r in top_src_ips],
        "top_event_types": [dict(r) for r in top_event_types],
    }


@router.get("/tenants")
async def tenants(_: Claims = Depends(require_admin)) -> list[str]:
    """For the admin's tenant switcher: every tenant that has users or ingest keys."""
    async with db.pool.acquire() as conn:
        rows = await conn.fetch("SELECT tenant FROM users UNION SELECT tenant FROM api_keys ORDER BY 1")
    return [r["tenant"] for r in rows]
