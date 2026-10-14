"""The ClickHouse events table, created (or updated) when the backend starts.

Design, and why:
- ORDER BY (tenant, ts, fingerprint): almost every question is "this tenant, this time range",
  so ClickHouse reads only that slice of the sorted data. The fingerprint at the end makes
  ReplacingMergeTree drop exact duplicates of the same event when it merges parts.
- PARTITION BY day + TTL: logs older than RETENTION_DAYS are deleted by ClickHouse itself.
- LowCardinality for columns with few distinct values (source, action, vendor…): stored as a
  small dictionary, so they compress to almost nothing and filter fast.
- Skip indexes (bloom filters) let a search for one IP, user or word skip most blocks unread.
- raw (the original log) is compressed with ZSTD, the biggest column by far.
"""
import asyncio
import logging

from .clickhouse import ch
from .config import settings

log = logging.getLogger("clickhouse")

EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events
(
    id               UInt64,                          -- time-ordered, made by the backend
    ts               DateTime64(3, 'UTC'),            -- "@timestamp"
    ingested_at      DateTime64(3, 'UTC') DEFAULT now64(3),
    tenant           LowCardinality(String),
    source           LowCardinality(String),
    vendor           LowCardinality(Nullable(String)),
    product          LowCardinality(Nullable(String)),
    event_type       LowCardinality(Nullable(String)),
    event_subtype    Nullable(String),
    severity         Nullable(UInt8),
    action           LowCardinality(Nullable(String)),
    src_ip           Nullable(String),                -- text: IPv4 and IPv6 in one column
    src_port         Nullable(UInt16),
    dst_ip           Nullable(String),
    dst_port         Nullable(UInt16),
    protocol         LowCardinality(Nullable(String)),
    username         Nullable(String),
    host             Nullable(String),
    process          Nullable(String),
    url              Nullable(String),
    http_method      LowCardinality(Nullable(String)),
    status_code      Nullable(UInt16),
    rule_name        Nullable(String),
    rule_id          Nullable(String),
    cloud_account_id Nullable(String),
    cloud_region     LowCardinality(Nullable(String)),
    cloud_service    LowCardinality(Nullable(String)),
    src_country      LowCardinality(Nullable(String)),
    raw              String CODEC(ZSTD(3)),           -- original payload as JSON text
    tags             Array(LowCardinality(String)),
    fingerprint      FixedString(64),                 -- sha256 hex of tenant + source + raw

    INDEX idx_src_ip   src_ip     TYPE bloom_filter GRANULARITY 4,
    INDEX idx_user     username   TYPE bloom_filter GRANULARITY 4,
    INDEX idx_host     host       TYPE bloom_filter GRANULARITY 4,
    INDEX idx_id       id         TYPE bloom_filter GRANULARITY 4,
    INDEX idx_fp       fingerprint TYPE bloom_filter GRANULARITY 4,
    INDEX idx_raw      raw        TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree
PARTITION BY toDate(ts)
ORDER BY (tenant, ts, fingerprint)
TTL toDateTime(ts) + INTERVAL {days} DAY
"""


# Ready-made totals per (tenant, minute, source), kept up to date by ClickHouse itself: the
# materialized view runs on every insert into `events` and adds its counts here. The dashboard's
# totals, timeline and breakdowns read these few rows instead of scanning every log.
# SummingMergeTree adds up rows with the same key when it merges, so queries use sum().
MINUTELY_TABLE = """
CREATE TABLE IF NOT EXISTS events_minutely
(
    tenant        LowCardinality(String),
    minute        DateTime('UTC'),
    source        LowCardinality(String),
    n             UInt64,
    critical      UInt64,   -- severity 9-10
    high          UInt64,   -- 7-8
    medium        UInt64,   -- 4-6
    low           UInt64,   -- 0-3
    unknown       UInt64,   -- no severity
    auth_failures UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toDate(minute)
ORDER BY (tenant, minute, source)
TTL minute + INTERVAL {days} DAY
"""

MINUTELY_SELECT = """
SELECT tenant, toStartOfMinute(ts) AS minute, source,
       count() AS n,
       countIf(severity >= 9) AS critical,
       countIf(severity BETWEEN 7 AND 8) AS high,
       countIf(severity BETWEEN 4 AND 6) AS medium,
       countIf(severity <= 3) AS low,
       countIf(isNull(severity)) AS unknown,
       countIf(has(tags, 'auth_failure')) AS auth_failures
FROM events
"""

MINUTELY_VIEW = "CREATE MATERIALIZED VIEW IF NOT EXISTS events_minutely_mv TO events_minutely AS " + MINUTELY_SELECT + \
    " GROUP BY tenant, minute, source"


async def _ensure_minutely(days: int) -> None:
    """Create the totals table and its view. The view only sees inserts made after it exists,
    so the first time, also add up the events already stored (those that arrived before)."""
    exists = await ch.query("SELECT name FROM system.tables WHERE database = currentDatabase() "
                            "AND name = 'events_minutely_mv'")
    await ch.command(MINUTELY_TABLE.format(days=days))
    if exists:
        return
    [now] = await ch.query("SELECT now64(3) AS t")
    await ch.command(MINUTELY_VIEW)
    # Events that arrived before the view existed; later ones are counted by the view itself.
    await ch.command("INSERT INTO events_minutely " + MINUTELY_SELECT +
                     " WHERE ingested_at < {cutoff:DateTime64(3, 'UTC')} GROUP BY tenant, minute, source",
                     {"cutoff": now["t"]})
    log.info("created events_minutely and filled it from existing events")


async def ensure_schema(attempts: int = 30) -> None:
    """Create the table, and keep its TTL in step with RETENTION_DAYS. Retries while ClickHouse starts."""
    for i in range(attempts):
        try:
            days = int(settings.retention_days)
            await ch.command(EVENTS_TABLE.format(days=days))
            await _ensure_minutely(days)
            # Changing a TTL rewrites existing parts, so only do it when RETENTION_DAYS changed.
            [row] = await ch.query("SELECT create_table_query AS q FROM system.tables "
                                   "WHERE database = currentDatabase() AND name = 'events'")
            # ClickHouse stores "INTERVAL 7 DAY" as "toIntervalDay(7)".
            if f"toIntervalDay({days})" not in row["q"] and f"INTERVAL {days} DAY" not in row["q"]:
                await ch.command(f"ALTER TABLE events MODIFY TTL toDateTime(ts) + INTERVAL {days} DAY")
                await ch.command(f"ALTER TABLE events_minutely MODIFY TTL minute + INTERVAL {days} DAY")
            return
        except Exception as exc:  # noqa: BLE001 - not up yet: wait and retry, then give up loudly
            if i == attempts - 1:
                raise
            log.warning("waiting for ClickHouse (%s)", exc)
            await asyncio.sleep(2)
