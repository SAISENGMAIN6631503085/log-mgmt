-- Initial schema. Applied once by app/migrate.py; never edit after it has shipped —
-- add a new numbered file instead.

-- ---------------------------------------------------------------------------
-- events: one row per normalized event (common schema, see CLAUDE.md).
-- Partitioned by day on ts so retention is "DROP TABLE <old partition>" (instant,
-- no vacuum bloat) and time-range queries only scan the relevant days.
-- ---------------------------------------------------------------------------
CREATE TABLE events (
    id              bigint GENERATED ALWAYS AS IDENTITY,
    ts              timestamptz NOT NULL,              -- "@timestamp" in the API
    tenant          text        NOT NULL,
    source          text        NOT NULL CHECK (source IN
                        ('firewall','network','api','crowdstrike','aws','m365','ad')),
    vendor          text,
    product         text,
    event_type      text,
    event_subtype   text,
    severity        smallint    CHECK (severity BETWEEN 0 AND 10),
    action          text        CHECK (action IN
                        ('allow','deny','create','delete','login','logout','alert','quarantine')),
    src_ip          inet,       -- inet (not text) so we can query by subnet: src_ip << '10.0.0.0/8'
    src_port        integer     CHECK (src_port BETWEEN 0 AND 65535),
    dst_ip          inet,
    dst_port        integer     CHECK (dst_port BETWEEN 0 AND 65535),
    protocol        text,
    username        text,       -- "user" in the API; renamed because USER is a reserved word in SQL
    host            text,
    process         text,
    url             text,
    http_method     text,
    status_code     integer,
    rule_name       text,
    rule_id         text,
    cloud_account_id text,
    cloud_region    text,
    cloud_service   text,
    raw             jsonb       NOT NULL,              -- original payload, always kept
    _tags           text[]      NOT NULL DEFAULT '{}',
    ingested_at     timestamptz NOT NULL DEFAULT now(),
    -- A primary key on a partitioned table must include the partition key.
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

-- Indexes declared on the parent are created on every partition automatically.
-- Every query is tenant-scoped and time-bounded, so (tenant, ts) is the main access path.
CREATE INDEX events_tenant_ts_idx   ON events (tenant, ts DESC);
-- Alert rule: failed logins per (tenant, src_ip) in the last 5 minutes.
CREATE INDEX events_tenant_src_ts_idx ON events (tenant, src_ip, ts DESC);
-- Free-form search on original fields (raw @> '{"k":"v"}') and tag filters (_tags @> '{auth_failure}').
CREATE INDEX events_raw_gin_idx     ON events USING GIN (raw jsonb_path_ops);
CREATE INDEX events_tags_gin_idx    ON events USING GIN (_tags);

-- Creates the partition for one UTC day if missing. Idempotent, so the startup job,
-- the daily retention job and ingest (for back-dated events) can all call it safely.
-- No DEFAULT partition on purpose: it would hold rows that block creating the real
-- day partition later, and it could never be dropped by retention.
CREATE FUNCTION ensure_event_partition(day date) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    part text := format('events_%s', to_char(day, 'YYYYMMDD'));
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
        part,
        (day::timestamp AT TIME ZONE 'UTC'),
        ((day + 1)::timestamp AT TIME ZONE 'UTC'));
END;
$$;

-- ---------------------------------------------------------------------------
-- users: login accounts. Viewers are bound to one tenant; admins can switch.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,                       -- bcrypt/argon2, never plaintext
    role          text NOT NULL CHECK (role IN ('admin','viewer')),
    tenant        text NOT NULL,                       -- admin: default tenant; viewer: the only tenant
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- api_keys: per-tenant keys for POST /api/ingest (X-API-Key header).
-- Stored as SHA-256, not bcrypt: keys are long random strings (no brute-force risk
-- like passwords), and a deterministic hash lets us look the key up by index.
-- ---------------------------------------------------------------------------
CREATE TABLE api_keys (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant      text NOT NULL,
    name        text NOT NULL,                         -- human label, e.g. "firewall-01"
    key_hash    text NOT NULL UNIQUE,                  -- hex sha256 of the full key
    key_prefix  text NOT NULL,                         -- first chars, shown in UI to identify the key
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz                            -- soft delete keeps an audit trail
);

-- ---------------------------------------------------------------------------
-- alerts: output of the alert worker.
-- ---------------------------------------------------------------------------
CREATE TABLE alerts (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant        text NOT NULL,
    rule_id       text NOT NULL,                       -- e.g. "brute_force_login"
    rule_name     text NOT NULL,
    severity      smallint NOT NULL CHECK (severity BETWEEN 0 AND 10),
    src_ip        inet,
    event_count   integer NOT NULL,                    -- how many events matched
    window_start  timestamptz NOT NULL,
    window_end    timestamptz NOT NULL,
    details       jsonb NOT NULL DEFAULT '{}',
    status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    webhook_sent_at timestamptz                        -- NULL = not sent (or no webhook configured)
);
-- De-duplication check: "is there an alert for (tenant, rule, src_ip) newer than now - window?"
CREATE INDEX alerts_dedup_idx ON alerts (tenant, rule_id, src_ip, created_at DESC);
CREATE INDEX alerts_tenant_created_idx ON alerts (tenant, created_at DESC);
