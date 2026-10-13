"""Alert rules for the website's "Rules" page: see them (everyone), tune them (admins).

The rules themselves live in code (app/alerting.py). A tenant can only turn a rule on or off
and change its threshold; those choices are stored in rule_settings.
"""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import db
from ..alerting import RULES, RULES_BY_ID, Rule
from ..auth import Claims, require_admin, resolve_tenant, scoped_tenant

router = APIRouter(prefix="/api/rules", tags=["rules"])


class RuleSettings(BaseModel):
    enabled: bool
    threshold: int = Field(ge=1, le=10_000)


def _rule_to_api(rule: Rule, setting, open_alerts: int) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "group_by": rule.group_by,
        "window_minutes": int(rule.window.total_seconds() // 60),
        "default_threshold": rule.threshold,
        "threshold": setting["threshold"] if setting else rule.threshold,
        "enabled": setting["enabled"] if setting else True,
        "open_alerts": open_alerts,
    }


async def _load(conn, tenant: str) -> tuple[dict, dict]:
    settings_rows = await conn.fetch("SELECT rule_id, enabled, threshold FROM rule_settings WHERE tenant = $1", tenant)
    open_rows = await conn.fetch(
        "SELECT rule_id, count(*) AS n FROM alerts WHERE tenant = $1 AND status = 'open' GROUP BY rule_id", tenant)
    return {r["rule_id"]: r for r in settings_rows}, {r["rule_id"]: r["n"] for r in open_rows}


@router.get("")
async def list_rules(tenant: str = Depends(scoped_tenant)) -> dict[str, Any]:
    async with db.pool.acquire() as conn:
        settings, open_alerts = await _load(conn, tenant)
    return {"tenant": tenant, "rules": [_rule_to_api(r, settings.get(r.id), open_alerts.get(r.id, 0)) for r in RULES]}


@router.put("/{rule_id}")
async def update_rule(rule_id: str, body: RuleSettings, tenant: str | None = None,
                      user: Claims = Depends(require_admin)) -> dict[str, Any]:
    """Admin only. Takes effect on the alert worker's next run (within a minute)."""
    rule = RULES_BY_ID.get(rule_id)
    if rule is None:
        raise HTTPException(404, "rule not found")
    scoped = resolve_tenant(user, tenant)
    async with db.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO rule_settings (tenant, rule_id, enabled, threshold) VALUES ($1, $2, $3, $4)
               ON CONFLICT (tenant, rule_id) DO UPDATE
               SET enabled = EXCLUDED.enabled, threshold = EXCLUDED.threshold, updated_at = now()""",
            scoped, rule.id, body.enabled, body.threshold)
        settings, open_alerts = await _load(conn, scoped)
    return _rule_to_api(rule, settings.get(rule.id), open_alerts.get(rule.id, 0))
