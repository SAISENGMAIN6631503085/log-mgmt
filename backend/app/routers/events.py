"""Reading events. Search filters come in the next step; this already enforces tenant scoping."""
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query

from .. import db
from ..auth import scoped_tenant

router = APIRouter(prefix="/api/events", tags=["events"])


def row_to_api(r) -> dict[str, Any]:
    """DB row -> common-schema JSON (`username` -> `user`, `ts` -> `@timestamp`)."""
    d = dict(r)
    d["@timestamp"] = d.pop("ts").isoformat()
    d["user"] = d.pop("username")
    for k in ("src_ip", "dst_ip"):
        d[k] = str(d[k]) if d[k] is not None else None
    d.pop("ingested_at", None)
    return d


@router.get("")
async def list_events(
    tenant: str = Depends(scoped_tenant),
    limit: int = Query(50, ge=1, le=500),
    before: datetime | None = Query(None, description="Only events older than this (for paging)"),
) -> dict[str, Any]:
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM events
               WHERE tenant = $1 AND ($2::timestamptz IS NULL OR ts < $2)
               ORDER BY ts DESC LIMIT $3""",
            tenant, before, limit,
        )
    return {"tenant": tenant, "events": [row_to_api(r) for r in rows]}
