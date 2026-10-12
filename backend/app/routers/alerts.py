from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from .. import db
from ..alerting import alert_to_api
from ..auth import Claims, require_admin, resolve_tenant, scoped_tenant

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    tenant: str = Depends(scoped_tenant),
    status: Literal["open", "acknowledged"] | None = None,
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM alerts WHERE tenant = $1 AND ($2::text IS NULL OR status = $2)
               ORDER BY created_at DESC LIMIT $3""",
            tenant, status, limit)
    return {"tenant": tenant, "alerts": [alert_to_api(r) for r in rows]}


@router.post("/{alert_id}/ack")
async def acknowledge(alert_id: int, tenant: str | None = None, user: Claims = Depends(require_admin)) -> dict:
    """Viewers are read-only, so only admins can acknowledge."""
    scoped = resolve_tenant(user, tenant)
    async with db.pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE alerts SET status = 'acknowledged' WHERE id = $1 AND tenant = $2 RETURNING *", alert_id, scoped)
    if row is None:
        raise HTTPException(404, "alert not found")
    return alert_to_api(row)
