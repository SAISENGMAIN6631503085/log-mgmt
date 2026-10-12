"""Event search. Every query is scoped to the tenant from `scoped_tenant` (see auth.py)."""
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import db
from ..auth import scoped_tenant
from ..normalizers.common import Action, Source
from ..search import SearchFilters, build_search, encode_cursor

router = APIRouter(prefix="/api/events", tags=["events"])

DEFAULT_WINDOW = timedelta(hours=24)


def row_to_api(r) -> dict[str, Any]:
    """DB row -> common-schema JSON (`username` -> `user`, `ts` -> `@timestamp`)."""
    d = dict(r)
    d["@timestamp"] = d.pop("ts").isoformat()
    d["user"] = d.pop("username")
    for k in ("src_ip", "dst_ip"):
        d[k] = str(d[k]) if d[k] is not None else None
    d.pop("ingested_at", None)
    d.pop("fingerprint", None)  # internal dedup hash (bytes), not part of the schema
    return d


@router.get("")
async def search_events(
    tenant: str = Depends(scoped_tenant),
    start: datetime | None = Query(None, alias="from", description="Default: 24h before `to`"),
    end: datetime | None = Query(None, alias="to", description="Default: now"),
    source: list[Source] = Query([], description="Repeat for several: ?source=aws&source=m365"),
    action: list[Action] = Query([]),
    severity_min: int | None = Query(None, ge=0, le=10),
    src_ip: str | None = Query(None, description="IP or CIDR, e.g. 10.0.0.0/8"),
    dst_ip: str | None = Query(None, description="IP or CIDR"),
    user: str | None = None,
    host: str | None = None,
    event_type: str | None = None,
    tag: str | None = Query(None, description="e.g. auth_failure"),
    q: str | None = Query(None, max_length=200, description="Free text, case-insensitive"),
    cursor: str | None = Query(None, description="next_cursor from the previous page"),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    end = end or datetime.now(timezone.utc)
    start = start or end - DEFAULT_WINDOW
    # Query params without a zone are read as UTC, like everything else in the system.
    start, end = (t if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in (start, end))
    if start >= end:
        raise HTTPException(422, "`from` must be before `to`")

    filters = SearchFilters(start=start, end=end, sources=source, actions=action, severity_min=severity_min,
                            src_ip=src_ip, dst_ip=dst_ip, user=user, host=host, event_type=event_type,
                            tag=tag, q=q, cursor=cursor, limit=limit)
    try:
        sql, args = build_search(tenant, filters)
    except ValueError as exc:  # bad IP/CIDR or cursor
        raise HTTPException(422, str(exc)) from None

    async with db.pool.acquire() as conn:
        rows = await conn.fetch(sql, *args)

    has_more = len(rows) > limit
    rows = rows[:limit]
    return {
        "tenant": tenant,
        "from": start.isoformat(),
        "to": end.isoformat(),
        "events": [row_to_api(r) for r in rows],
        "next_cursor": encode_cursor(rows[-1]["ts"], rows[-1]["id"]) if has_more else None,
    }


@router.get("/{event_id}")
async def get_event(event_id: int, tenant: str = Depends(scoped_tenant)) -> dict[str, Any]:
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM events WHERE id = $1 AND tenant = $2", event_id, tenant)
    if row is None:
        # 404 (not 403) for another tenant's event: don't confirm that the id exists.
        raise HTTPException(404, "event not found")
    return row_to_api(row)
