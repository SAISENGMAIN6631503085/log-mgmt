"""Alert worker: runs every ALERT_INTERVAL_SECONDS inside the backend process.

Every rule has the same shape: ">= threshold matching events from the same IP (or host),
within the same tenant, inside any `window` of *event* time". So one detection query and one
de-duplication path serve all rules; a rule is just a filter, a grouping column and defaults.

Why event time and not "the last 5 minutes": logs often arrive late (a file uploaded an hour
later, a syslog buffer flushing). Each run looks at matching events that *arrived* recently,
then checks their event-time history, so a late-delivered attack is still caught.

Admins can turn a rule off or change its threshold per tenant (table rule_settings).
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import asyncpg
import httpx

from . import db, geoip
from .clickhouse import ch
from .config import settings
from .search import parse_ts

log = logging.getLogger("alerting")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str        # plain words, shown on the Rules page
    where: str              # ClickHouse SQL condition on events; fixed code, never user input
    group_by: str           # "src_ip" or "host": a fixed column name, never user input
    threshold: int          # default; tenants may override it
    window: timedelta
    severity: int


RULES = [
    Rule("brute_force_login", "Brute-force login",
         "Many failed sign-ins from one IP address: someone may be guessing passwords.",
         "has(tags, 'auth_failure')", "src_ip", 5, timedelta(minutes=5), 7),
    Rule("firewall_scan", "Firewall scan",
         "Many connections from one IP address blocked by the firewall: someone may be scanning for open ports.",
         "source = 'firewall' AND has(tags, 'blocked')", "src_ip", 20, timedelta(minutes=5), 6),
    Rule("malware_detected", "Malware detected",
         "CrowdStrike reported a high-severity threat (7 or more) on a computer.",
         "source = 'crowdstrike' AND severity >= 7", "host", 1, timedelta(minutes=5), 9),
]
RULES_BY_ID = {r.id: r for r in RULES}


# Kept for readers of the original single-rule version (and its tests).
RULE_ID = "brute_force_login"
WINDOW = RULES_BY_ID[RULE_ID].window

# Look at events ingested in this period. Bigger than the run interval so a slow or missed
# run doesn't leave gaps; overlap between runs is harmless because of de-duplication.
INGEST_LOOKBACK = timedelta(minutes=10)
WEBHOOK_RETRY_FOR = timedelta(hours=1)
_LOCK_ID = 7_340_002  # one evaluator at a time, even with several backend processes

def detect_sql(rule: Rule) -> str:
    """For each (tenant, group) that received a matching event recently, slide the rule's window
    over its matching events (by event time): `count() OVER` a RANGE frame = "matches in the
    window up to and including this one". Returns every window that reaches `min_threshold`.
    Only fixed strings from RULES and the window's whole milliseconds go into the text; the
    times and threshold are parameters. (A window frame's size must be a literal in ClickHouse.)
    """
    key, where = rule.group_by, rule.where
    ms = int(rule.window.total_seconds() * 1000)
    return f"""
SELECT tenant, gkey AS group_key, n, toString(window_start) AS window_start, toString(window_end) AS window_end
FROM (
    SELECT tenant, {key} AS gkey, ts AS window_end,
           count() OVER w AS n,
           min(ts) OVER w AS window_start
    FROM events
    WHERE ts >= {{oldest:DateTime64(3, 'UTC')}} AND ({where})
      AND (tenant, {key}) IN (
          SELECT tenant, {key} FROM events
          WHERE ingested_at >= {{since:DateTime64(3, 'UTC')}} AND ts >= {{oldest:DateTime64(3, 'UTC')}}
            AND {key} IS NOT NULL AND ({where}))
    WINDOW w AS (PARTITION BY tenant, {key} ORDER BY toUnixTimestamp64Milli(ts)
                 RANGE BETWEEN {ms} PRECEDING AND CURRENT ROW)
)
WHERE n >= {{min_threshold:UInt32}}
ORDER BY tenant, group_key, window_end
"""


async def _detect(rule: Rule, now: datetime, oldest: datetime, rule_settings: dict) -> list[dict]:
    """Qualifying windows for one rule. Events are in ClickHouse but per-tenant settings (on/off,
    threshold) are in Postgres, so they're applied here: the query uses the lowest threshold in
    play, then each tenant's own is checked."""
    mine = {t: st for (t, r), st in rule_settings.items() if r == rule.id}
    lowest = min([rule.threshold, *(st["threshold"] for st in mine.values() if st["enabled"])])
    rows = await ch.query(detect_sql(rule), {"oldest": oldest, "since": now - INGEST_LOOKBACK,
                                                 "min_threshold": lowest})
    out = []
    for r in rows:
        st = mine.get(r["tenant"])
        if st is not None and (not st["enabled"] or r["n"] < st["threshold"]):
            continue
        if st is None and r["n"] < rule.threshold:
            continue
        out.append({**r, "window_start": parse_ts(r["window_start"]), "window_end": parse_ts(r["window_end"])})
    return out


def merge_bursts(rows: list[dict], key: str = "src_ip") -> list[dict]:
    """Overlapping qualifying windows for the same (tenant, key) are one attack, not many.

    Input rows are sorted by (tenant, key, window_end). Output: one dict per burst with
    the overall start/end and the highest count seen in any single window.
    """
    bursts: list[dict] = []
    for r in rows:
        last = bursts[-1] if bursts else None
        if last and (last["tenant"], last[key]) == (r["tenant"], r[key]) \
                and r["window_start"] <= last["window_end"]:
            last["window_end"] = max(last["window_end"], r["window_end"])
            last["n"] = max(last["n"], r["n"])
        else:
            bursts.append(dict(r))
    return bursts


async def _upsert_alert(conn: asyncpg.Connection, rule: Rule, b: dict) -> int | None:
    """Create an alert for a burst, or fold it into a recent alert for the same
    (tenant, rule, group). Returns the new alert id, or None if it was merged.

    De-duplication: if an alert for this group ended less than one window before this burst
    starts (or overlaps it), it's the same ongoing attack; extend it instead of alerting again.
    """
    details_rows = await ch.query(
        f"""SELECT DISTINCT username, source, host, event_type FROM events
            WHERE tenant = {{tenant:String}} AND {rule.group_by} = {{gk:String}}
              AND ts >= {{s:DateTime64(3, 'UTC')}} AND ts <= {{e:DateTime64(3, 'UTC')}} AND ({rule.where})
            LIMIT 200""",
        {"tenant": b["tenant"], "gk": b["group_key"], "s": b["window_start"], "e": b["window_end"]})
    pick = lambda col: sorted({r[col] for r in details_rows if r[col]})[:20]  # noqa: E731
    details = {
        "users": pick("username"),
        "sources": pick("source"),
        "hosts": pick("host"),
        "event_types": pick("event_type"),
        "group_by": rule.group_by,
        "country": geoip.country(b["group_key"]) if rule.group_by == "src_ip" else None,
        "threshold": b["threshold"],
        "window_minutes": int(rule.window.total_seconds() // 60),
    }
    existing = await conn.fetchval(
        """SELECT id FROM alerts
           WHERE tenant = $1 AND rule_id = $2 AND group_key = $3
             AND window_end >= $4::timestamptz - $5::interval AND window_start <= $6::timestamptz + $5::interval
           ORDER BY window_end DESC LIMIT 1""",
        b["tenant"], rule.id, b["group_key"], b["window_start"], rule.window, b["window_end"])
    if existing:
        await conn.execute(
            """UPDATE alerts SET window_start = least(window_start, $2), window_end = greatest(window_end, $3),
                      event_count = greatest(event_count, $4), details = $5
               WHERE id = $1""",
            existing, b["window_start"], b["window_end"], b["n"], details)
        return None
    src_ip = b["group_key"] if rule.group_by == "src_ip" else None
    return await conn.fetchval(
        """INSERT INTO alerts (tenant, rule_id, rule_name, severity, src_ip, group_key, event_count,
                               window_start, window_end, details)
           VALUES ($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10) RETURNING id""",
        b["tenant"], rule.id, rule.name, rule.severity, src_ip, b["group_key"], b["n"],
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
        oldest = now - timedelta(days=settings.retention_days)
        rule_settings = {(r["tenant"], r["rule_id"]): dict(r) for r in
                         await conn.fetch("SELECT tenant, rule_id, enabled, threshold FROM rule_settings")}
        for rule in RULES:
            rows = await _detect(rule, now, oldest, rule_settings)
            for burst in merge_bursts(rows, key="group_key"):
                st = rule_settings.get((burst["tenant"], rule.id))
                burst["threshold"] = st["threshold"] if st else rule.threshold
                if (alert_id := await _upsert_alert(conn, rule, burst)) is not None:
                    created.append(alert_id)
                    log.info("alert %s: %s for %s (tenant %s, %s events)",
                             alert_id, rule.id, burst["group_key"], burst["tenant"], burst["n"])
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
