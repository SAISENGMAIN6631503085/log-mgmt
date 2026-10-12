"""Alert worker: runs every ALERT_INTERVAL_SECONDS inside the backend process.

Rule 1 (brute_force_login): >= 5 failed logins (tag auth_failure) from the same src_ip,
within the same tenant, inside any 5-minute window of *event* time.

Why event time and not "the last 5 minutes": logs often arrive late (a file uploaded an hour
later, a syslog buffer flushing). Each run looks at failures that *arrived* recently, then
checks their event-time history, so a late-delivered attack is still caught.
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

import asyncpg
import httpx

from . import db
from .config import settings

log = logging.getLogger("alerting")

RULE_ID = "brute_force_login"
RULE_NAME = "Brute-force login: 5+ failed logins from one IP within 5 minutes"
THRESHOLD = 5
WINDOW = timedelta(minutes=5)
SEVERITY = 7
# Look at failures ingested in this period. Bigger than the run interval so a slow or missed
# run doesn't leave gaps; overlap between runs is harmless because of de-duplication.
INGEST_LOOKBACK = timedelta(minutes=10)
WEBHOOK_RETRY_FOR = timedelta(hours=1)
_LOCK_ID = 7_340_002  # one evaluator at a time, even with several backend processes

# For each (tenant, src_ip) that received a failed login recently, slide a 5-minute window
# over its failures (by event time) and return every window that reaches the threshold.
# (count(*) OVER a RANGE frame = "failures in the 5 minutes up to and including this one".)
_DETECT_SQL = """
WITH candidates AS (
    SELECT DISTINCT tenant, src_ip FROM events
    WHERE ingested_at >= $1 AND _tags @> '{auth_failure}' AND src_ip IS NOT NULL
      AND ts >= $2                        -- lets Postgres skip partitions outside retention
),
windows AS (
    SELECT e.tenant, e.src_ip, e.ts AS window_end,
           count(*)  OVER w AS n,
           min(e.ts) OVER w AS window_start
    FROM events e JOIN candidates c USING (tenant, src_ip)
    WHERE e._tags @> '{auth_failure}' AND e.ts >= $2
    WINDOW w AS (PARTITION BY e.tenant, e.src_ip ORDER BY e.ts
                 RANGE BETWEEN $3::interval PRECEDING AND CURRENT ROW)
)
SELECT tenant, src_ip, n, window_start, window_end FROM windows
WHERE n >= $4
ORDER BY tenant, src_ip, window_end
"""


def merge_bursts(rows: list[dict]) -> list[dict]:
    """Overlapping qualifying windows for the same (tenant, src_ip) are one attack, not many.

    Input rows are sorted by (tenant, src_ip, window_end). Output: one dict per burst with
    the overall start/end and the highest count seen in any single 5-minute window.
    """
    bursts: list[dict] = []
    for r in rows:
        last = bursts[-1] if bursts else None
        if last and (last["tenant"], last["src_ip"]) == (r["tenant"], r["src_ip"]) \
                and r["window_start"] <= last["window_end"]:
            last["window_end"] = max(last["window_end"], r["window_end"])
            last["n"] = max(last["n"], r["n"])
        else:
            bursts.append(dict(r))
    return bursts


async def _upsert_alert(conn: asyncpg.Connection, b: dict) -> int | None:
    """Create an alert for a burst, or fold it into a recent alert for the same
    (tenant, rule, src_ip). Returns the new alert id, or None if it was merged.

    De-duplication: if an alert for this IP ended less than one WINDOW before this burst
    starts (or overlaps it), it's the same ongoing attack; extend it instead of alerting again.
    """
    details_rows = await conn.fetch(
        """SELECT DISTINCT username, source FROM events
           WHERE tenant = $1 AND src_ip = $2 AND _tags @> '{auth_failure}' AND ts BETWEEN $3 AND $4""",
        b["tenant"], b["src_ip"], b["window_start"], b["window_end"])
    details = {
        "users": sorted({r["username"] for r in details_rows if r["username"]}),
        "sources": sorted({r["source"] for r in details_rows}),
        "threshold": THRESHOLD,
        "window_minutes": int(WINDOW.total_seconds() // 60),
    }
    existing = await conn.fetchval(
        """SELECT id FROM alerts
           WHERE tenant = $1 AND rule_id = $2 AND src_ip = $3
             AND window_end >= $4::timestamptz - $5::interval AND window_start <= $6::timestamptz + $5::interval
           ORDER BY window_end DESC LIMIT 1""",
        b["tenant"], RULE_ID, b["src_ip"], b["window_start"], WINDOW, b["window_end"])
    if existing:
        await conn.execute(
            """UPDATE alerts SET window_start = least(window_start, $2), window_end = greatest(window_end, $3),
                      event_count = greatest(event_count, $4), details = $5
               WHERE id = $1""",
            existing, b["window_start"], b["window_end"], b["n"], details)
        return None
    return await conn.fetchval(
        """INSERT INTO alerts (tenant, rule_id, rule_name, severity, src_ip, event_count,
                               window_start, window_end, details)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id""",
        b["tenant"], RULE_ID, RULE_NAME, SEVERITY, b["src_ip"], b["n"],
        b["window_start"], b["window_end"], details)


def alert_to_api(r) -> dict:
    d = dict(r)
    d["src_ip"] = str(d["src_ip"]) if d["src_ip"] is not None else None
    for k in ("window_start", "window_end", "created_at", "webhook_sent_at"):
        d[k] = d[k].isoformat() if d[k] else None
    return d


async def send_webhook(url: str, payload: dict) -> None:
    """Separate function so tests can replace it. Raises on failure."""
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.post(url, json=payload)
        r.raise_for_status()


async def _deliver_webhooks(conn: asyncpg.Connection, now: datetime) -> int:
    """Send every alert not yet delivered (new ones, and earlier failures for up to an hour)."""
    url = settings.alert_webhook_url
    if not url:
        return 0
    pending = await conn.fetch(
        "SELECT * FROM alerts WHERE webhook_sent_at IS NULL AND created_at >= $1 ORDER BY id",
        now - WEBHOOK_RETRY_FOR)
    sent = 0
    for a in pending:
        try:
            await send_webhook(url, {"type": "alert", "alert": alert_to_api(a)})
        except (httpx.HTTPError, OSError) as exc:
            # Don't let one unreachable webhook stop the worker; retried on the next run.
            log.warning("webhook for alert %s failed: %s", a["id"], exc)
            continue
        await conn.execute("UPDATE alerts SET webhook_sent_at = $2 WHERE id = $1", a["id"], now)
        sent += 1
    return sent


async def run_once(conn: asyncpg.Connection, now: datetime | None = None) -> list[int]:
    """One evaluation pass. Returns ids of newly created alerts."""
    now = now or datetime.now(timezone.utc)
    created: list[int] = []
    async with conn.transaction():
        # xact lock: released automatically at commit/rollback, even if this run crashes.
        if not await conn.fetchval("SELECT pg_try_advisory_xact_lock($1)", _LOCK_ID):
            return created  # another backend process is already evaluating
        rows = await conn.fetch(_DETECT_SQL, now - INGEST_LOOKBACK,
                                now - timedelta(days=settings.retention_days), WINDOW, THRESHOLD)
        for burst in merge_bursts([dict(r) for r in rows]):
            if (alert_id := await _upsert_alert(conn, burst)) is not None:
                created.append(alert_id)
                log.info("alert %s: %s from %s (tenant %s, %s failures)",
                         alert_id, RULE_ID, burst["src_ip"], burst["tenant"], burst["n"])
    # Outside the transaction: a slow webhook must not hold the lock or roll back alerts.
    await _deliver_webhooks(conn, now)
    return created


async def worker_loop() -> None:
    """Started from the app lifespan; cancelled on shutdown."""
    while True:
        try:
            async with db.pool.acquire() as conn:
                await run_once(conn)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a bad run must not kill the loop; it's logged and retried
            log.exception("alert worker run failed")
        await asyncio.sleep(settings.alert_interval_seconds)
