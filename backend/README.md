# Backend (FastAPI)

- `app/main.py` – app + `/health` (returns 503 if Postgres or ClickHouse is unreachable)
- `app/config.py` – settings from env vars (documented in `/.env.example`)
- `app/db.py` – asyncpg connection pool
- `app/seed.py` – `make seed` entry point
- `app/migrate.py` + `app/migrations/*.sql` – schema migrations, applied on startup

## Database schema
Two databases, each for what it's good at (why: `docs/architecture.md`):
- **ClickHouse** stores the events (logs): huge, written once, summarized all the time.
- **PostgreSQL** stores the small data that changes: users, keys, alerts, rule settings.

### PostgreSQL
Migrations run automatically when the backend starts. Each `.sql` file runs once, in name
order, in its own transaction, and is recorded in `schema_migrations`. A Postgres advisory
lock stops two backends from migrating at the same time. To change the schema, add a new
numbered file. Never edit a migration that has already shipped.

| Table | Purpose |
|-------|---------|
| `users` | login accounts: bcrypt/argon2 hash, `role` admin/viewer, `tenant` |
| `api_keys` | per-tenant ingest keys, stored as SHA-256 hashes |
| `alerts` | alert worker output, indexed for (tenant, rule, src_ip) de-duplication |
| `rule_settings` | per-tenant rule on/off and threshold |
| `login_failures` | recent failed sign-ins, for throttling |

Events were in a day-partitioned Postgres table until migration 007 moved them to ClickHouse.

### ClickHouse (`app/ch_schema.py`, created or updated at startup)
| Table | Purpose |
|-------|---------|
| `events` | normalized events: `ReplacingMergeTree`, `PARTITION BY toDate(ts)` (one partition per UTC day), `ORDER BY (tenant, ts, fingerprint)`, `TTL` = `RETENTION_DAYS` |
| `events_minutely` | per-minute totals per (tenant, source, severity band), added to by the materialized view `events_minutely_mv` on every insert (`SummingMergeTree`, same TTL) |

- `ORDER BY (tenant, ts, …)`: data is stored sorted by tenant and time, so a tenant's time range
  is read without scanning anyone else's rows.
- `LowCardinality` for repeated strings (source, action…), bloom-filter skip indexes on IP, user,
  host and id, a token index on the raw log, ZSTD compression for `raw`.
- Ids are time-ordered and kept under 2^53, so browsers (JSON numbers are doubles) show them exactly.
- Queries go over ClickHouse's HTTP interface with `httpx`; values are always typed parameters
  (`{tenant:String}`), never pasted into SQL.
- Memory is capped in `clickhouse/config.d/small-server.xml` (650 MB for the server, 400 MB per
  query) and tuned with ClickHouse's low-memory settings: small background pools, one thread per
  query, no parallel parsing. Measured: about 250–350 MB idle and under 400 MB during the whole test
  suite, so it fits a 2 GB VM. On a bigger appliance, raise the limits or delete that file.

The schema field `user` is stored as the column `username`, because `USER` is a reserved word in
SQL; `_tags` is stored as `tags`.

- `app/routers/ingest.py` – ingestion endpoints (below)
- `app/auth.py` + `app/routers/auth.py` – login, JWT, tenant scoping
- `app/routers/events.py` – event search and single event (tenant-scoped)
- `app/search.py` – builds the ClickHouse search query (pure, unit-tested)
- `app/ch_stats.py` – the dashboard numbers, from ClickHouse
- `app/alerting.py` + `app/routers/alerts.py` – alert worker and alerts API
- `app/retention.py` – drops old days of events (hourly, and `make retention`)
- `app/api_keys.py` – per-tenant `X-API-Key` auth (keys stored as SHA-256)
- `app/events_store.py` + `app/ch_events.py` – storing events in ClickHouse (dedup, ids), timestamp window check
- `app/clickhouse.py` – the small ClickHouse HTTP client

Tests live in `/tests` at the repo root; run them with `make test`.

## Normalizers (`app/normalizers/`)
Each source has one pure function, `normalize(payload, tenant) -> Event`, that maps it to the
common schema. It does no DB or network I/O, so each one is unit-tested against `/samples`.
`Event` (`common.py`) is a Pydantic model, so a mapping bug such as severity 42 or a bad IP fails loudly.

| Source | Input | Notes |
|--------|-------|-------|
| `firewall` | syslog line, key=value | accept/permit/pass → `allow`; deny/drop/block/reject → `deny` |
| `network` | syslog line | `event_type` falls back to the program tag (e.g. `%LINK-3-UPDOWN`) |
| `api` | JSON object | auth-related `*_failed` → `login` + `auth_failure`; tenant in body ignored |
| `crowdstrike` | Falcon DetectionSummaryEvent | severity 1–5 ×2; quarantined → `quarantine`, else `alert` |
| `aws` | CloudTrail record (`iter_records` unwraps `{"Records": [...]}`) | failed ConsoleLogin → `auth_failure`; Root → `root_activity` |
| `m365` | Management Activity audit record | failed status → `login` + `auth_failure`; forwarding inbox rule flagged |
| `ad` | Windows Security event (CSV row/JSON) | 4625 → `login` + `auth_failure`; 4624/4634/4720/4726/4740 mapped |

Shared rules:
- `unify_aliases` renames `ip`/`src` → `src_ip`, `dst` → `dst_ip`, `spt`/`dpt` → ports, and `proto` → `protocol`.
- `clean_ip` turns hostnames, `-` and `ip:port` into a clean IP or `None`.
- `parse_ts` treats timestamps without a time zone as UTC.

Syslog (`syslog.py`):
- `<PRI> % 8` maps to severity 10/9/8/7/5/3/2/0.
- Timestamps without a year use the current year in UTC. A line more than one day "in the future"
  is moved to the previous year, which handles a Dec 31 line arriving on Jan 1.
- The tenant comes from the sender IP via `SYSLOG_TENANT_MAP`, else `DEFAULT_TENANT`.

## How each feature uses ClickHouse
- **Ingest** stores each batch in ClickHouse (`app/ch_events.py`). If ClickHouse is down, ingest
  answers 503 and stores nothing, so the sender retries (Vector keeps a buffer and retries itself).
- **Dashboard** (`/api/stats`, `app/ch_stats.py`): counts, timeline and breakdowns read
  `events_minutely`, so they cost the same at any volume (precision: one minute). Top lists read
  the events table. The response says which engine answered and how long it took (`engine`),
  shown on the Overview.
- **Search** (`/api/events`, `/api/events/{id}`): keyset paging on `(ts, id)`, see below.
- **Alerts**: detection counts events in each window with a window function
  (`RANGE BETWEEN <window> PRECEDING`). Per-tenant rule settings are in Postgres and applied in Python.
- **Retention** drops whole days (`ALTER TABLE … DROP PARTITION`), see below.

Tests store events through the app's own write path (`store_events` in `tests/conftest.py`).
Their ClickHouse data is deleted in one statement at the end of the run: a ClickHouse `DELETE`
rewrites files in the background, and one per test piled up.

## Enrichment: country of the source IP (`app/geoip.py`)
After normalizing, ingest looks up the country of `src_ip` and stores it as `src_country`
(two-letter code, migration 005). It's then a search filter (`?country=TH`), a dashboard table
(top countries) and part of each IP-based alert.

- Data: DB-IP "IP to Country Lite", free under CC BY 4.0. The website links to db-ip.com, as the licence requires.
- `fetch_geoip.py` downloads it while the image is built (this month's file, or last month's).
  Lookups read the local file, so no log data leaves the server. Refresh it with
  `docker compose build --no-cache backend`.
- Private and reserved addresses (10.x, 192.168.x, and the documentation ranges used in the
  assignment samples) have no country. Without the file, enrichment is off and nothing else changes.

## Ingestion endpoints
All three normalize events, store the valid ones, and report the rest:
`{"accepted": n, "duplicates": d, "rejected_count": m, "rejected": [{"index": i, "error": "..."}]}`.
One bad event never blocks the rest of the batch.

**Duplicates** (`app/ch_events.py`): an event already stored is counted in `duplicates` and not stored again.
Re-uploading a file or Vector retrying a batch is therefore safe.
- `fingerprint = sha256(json([tenant, source, raw]) with sorted keys)`, so it is the same however
  the JSON was formatted. The app always computes it, so a caller can't supply or forge one.
- A duplicate is the same fingerprint **at the same time** (`ts`), so identical content at a
  different time is a different event.
- ClickHouse has no unique constraint, so the app checks which (fingerprint, ts) pairs already
  exist before inserting; counts are right at once. `ReplacingMergeTree` with the same key also
  removes any repeat that slips through (two inserts at the same moment) when it merges.
- The same event sent by two tenants is stored for both.
- Events with no timestamp get the receipt time, so they are never treated as duplicates. Two
  such sends are kept, rather than risk dropping real repeated events.
- Trade-off: two genuinely separate events with byte-identical payloads *and* identical
  timestamps are stored once. Real sources include unique IDs or ports (CloudTrail `eventID`,
  M365 `Id`, AD `IpPort`), so this mostly affects hand-made test data.

| Endpoint | Auth | Body |
|----------|------|------|
| `POST /api/ingest` (alias `POST /ingest`) | `X-API-Key` | one JSON event or an array. The normalizer comes from `?source=`, else each event's own `"source"` field, else `api`. A `{"Records": [...]}` body is CloudTrail. |
| `POST /api/ingest/file` | `X-API-Key` | multipart: `source` + `file` (.json, .ndjson/.jsonl, .csv, .log/.txt), max 50 MB |
| `POST /api/ingest/upload` | login token, **admin** | the same upload for the website's **Add logs** page. The tenant is the one being viewed (`?tenant=`, same rule as every read endpoint); viewers get 403 because they're read-only. |
| `POST /api/ingest/syslog` | `X-Ingest-Token` | internal, Vector only; blocked by Caddy from outside |

API keys are managed by admins, per tenant (`?tenant=`, same rule as every read endpoint):

| Endpoint | What it does |
|----------|--------------|
| `GET /api/keys` | List the tenant's keys: name, prefix (`lm_xxxxx…`), created, revoked. Never the key or its hash. |
| `POST /api/keys` `{"name": "shop website"}` | Create a key. The full key is in this response **only**; it's stored as a SHA-256 hash. |
| `POST /api/keys/{id}/revoke` | Revoke it: it stops working at once. The row stays (audit trail). Another tenant's key → 404. |

Rules:
- **The tenant always comes from the API key** (or, for syslog, from the sender IP). An event whose own
  `tenant` field names a *different* tenant is **rejected** with a clear message. It is not silently
  re-labelled, so a wrong key or a cross-tenant write attempt is visible.
- Each normalizer accepts the vendor's real format (CloudTrail, M365 Management API, Falcon, Windows
  event export) **and** the flat format used in the assignment's samples (`@timestamp`, `event_type`, `user`, `ip`, `cloud: {...}`).
- At most 10,000 events per request; above that the request gets 413.
- Events older than `RETENTION_DAYS` or more than 1 day in the future are **stored at the receipt time,
  tagged `time_adjusted`**, and keep their original timestamp in `raw`. The response counts them in
  `time_adjusted`. Storing them at their real (old) time would get them deleted by retention within
  the hour, and rejecting them would drop real activity from devices with a wrong clock or from old sample files.
- Demo keys come from `SEED_API_KEYS` and are created by `make seed`.

```
curl -k https://localhost/api/ingest -H "X-API-Key: lm_demoA_dev_key_change_me" \
     -H "content-type: application/json" -d '{"event_type":"login_failed","user":"alice","ip":"203.0.113.7"}'
curl -k https://localhost/api/ingest/file -H "X-API-Key: lm_demoA_dev_key_change_me" \
     -F source=aws -F file=@samples/aws_cloudtrail.json
```

## Login and tenant isolation
`POST /api/auth/login` takes `{"username", "password"}` and returns a JWT. Send it as
`Authorization: Bearer <token>`. The token's claims are `sub`, `role` (admin|viewer) and `tenant`.
`GET /api/auth/me` shows the current claims.

**Sign-in throttling** (migration 006, `routers/auth.py`): 5 failed sign-ins for one username within
5 minutes pause that username, and 20 from one client address pause that address, until the oldest
counted failure leaves the window (sliding, so no unlock job). The answer is `429` with a
`Retry-After` header, and it's the same for usernames that don't exist, so it never reveals which
accounts are real. A successful sign-in clears that username's count. The client address is the
real one: uvicorn trusts `X-Forwarded-For` only because Caddy, the only way in, overwrites it.
Limits: `LOGIN_MAX_FAILURES`, `LOGIN_IP_MAX_FAILURES`, `LOGIN_LOCK_MINUTES`.

| Who | `GET /api/events` | `GET /api/events?tenant=demoB` |
|-----|-------------------|--------------------------------|
| viewerA (demoA) | demoA events | **403** |
| admin | admin's default tenant | demoB events |
| no / bad token | **401** | **401** |

- **All tenant decisions happen in `resolve_tenant()` / `scoped_tenant`** (`app/auth.py`).
  Data endpoints take their tenant from that dependency and put it in the SQL `WHERE`.
  They never read a tenant from the body or a header.
- Passwords are hashed with bcrypt.
- Wrong password and unknown user return the same error and take the same time, because a
  dummy hash is checked, so attackers can't find valid usernames.
- JWTs are HS256, and the algorithm is fixed on decode, so `alg: none` tokens are rejected.
- The backend refuses to start if `JWT_SECRET` is shorter than 32 characters or still the
  example value.
- Tokens are stateless, so a role change takes effect when the old token expires (`JWT_EXPIRE_MINUTES`).

`make seed` creates `admin` (default tenant demoA), `viewerA` (demoA) and `viewerB` (demoB)
with the passwords from `SEED_ADMIN_PASSWORD` / `SEED_VIEWER_PASSWORD`.

## Search
`GET /api/events` needs a Bearer token. All filters are optional and combine with AND.

| Param | Example | Meaning |
|-------|---------|---------|
| `from`, `to` | `2026-10-12T08:00:00Z` | time range; default is the last 24 h; no zone means UTC |
| `source` | `?source=aws&source=m365` | repeat to match any of several |
| `action` | `deny` | repeatable, like `source` |
| `severity_min` | `7` | 0–10 |
| `src_ip`, `dst_ip` | `203.0.113.50` or `10.0.0.0/8` | an IP or a whole network |
| `user`, `host` | `administrator` | exact match, any case |
| `event_type` | `ConsoleLogin` | exact |
| `tag` | `auth_failure` | |
| `q` | `mimikatz` | free text over the main fields **and the original log** (`raw`), any case |
| `limit`, `cursor` | `50` | page size (max 500); pass `next_cursor` to get the next page |
| `tenant` | `demoB` | admin only (see above) |

`GET /api/events/{id}` returns one event, or 404 if it belongs to another tenant (404 rather
than 403, so the response doesn't reveal that the id exists).

How it works:
- **No SQL injection.** Every value is sent as a query parameter; column names are fixed in code.
- **Fast.** Every query is filtered by tenant and time, and ClickHouse stores events sorted by
  `(tenant, ts)` in day partitions, so it reads only that tenant's slice of those days.
- **Keyset paging (`(ts, id) < cursor`) instead of OFFSET.** Deep pages stay fast, and new
  events arriving between page loads don't cause duplicates or gaps.
- **One extra row instead of `COUNT(*)`.** Each query fetches one row more than the page
  size; if it arrives, there is a next page.

## Alerts
A background task inside the backend runs every `ALERT_INTERVAL_SECONDS` (60).

Every rule has one shape: **at least N matching events from the same IP (or computer), in the
same tenant, within W minutes.** So one detection query and one de-duplication path serve all
rules; a rule (in `RULES`, `app/alerting.py`) is just a SQL filter, a grouping column and defaults.

| Rule | Matches | Grouped by | Default | Severity |
|------|---------|-----------|---------|----------|
| `brute_force_login` | events tagged `auth_failure` (any source) | `src_ip` | 5 in 5 min | 7 |
| `firewall_scan` | firewall events tagged `blocked` | `src_ip` | 20 in 5 min | 6 |
| `malware_detected` | CrowdStrike events with severity ≥ 7 | `host` | 1 in 5 min | 9 |

**Per-tenant settings** (`rule_settings`, migration 004): admins can turn a rule off or change its
threshold for one tenant. No row means on, with the default threshold. The window is fixed per
rule, because a SQL window frame's size can't vary per row.

How it works:
- **Event time, not clock time.** Each run takes the groups (IPs or computers) whose matching
  events *arrived* in the last 10 minutes (indexed `ingested_at`, migration 002), then slides the
  rule's window over their matching events by `ts` (SQL `count(*) OVER (... RANGE '5 min' PRECEDING)`).
  Logs that arrive late, or come from an uploaded file, are still caught.
- **De-duplication.** Overlapping windows are one attack. If an alert for the same
  (tenant, rule, group) ended less than one window before the new burst, the existing alert is
  extended (`window_end`, `event_count`) instead of creating a new one. A new attack after a
  quiet period creates a new alert.
- **One evaluator.** `pg_try_advisory_xact_lock` makes a second backend process skip the run,
  so alerts are never doubled.
- **Webhook.** If `ALERT_WEBHOOK_URL` is set, each new alert is POSTed as
  `{"type": "alert", "alert": {...}}`. A failed delivery is logged, and retried on each run
  for up to an hour; `webhook_sent_at` records success. Delivery happens after the DB
  transaction commits, so a slow webhook never blocks or rolls back alerts.

API (Bearer token, tenant-scoped like search):
- `GET /api/alerts?status=open|acknowledged`. Each alert has `group_key` (the IP or computer) and
  `src_ip` (for IP-based rules).
- `POST /api/alerts/{id}/ack` (admin only; viewers are read-only)
- `GET /api/rules`: the rules with this tenant's settings and open-alert counts (everyone)
- `PUT /api/rules/{id}` `{"enabled": true, "threshold": 10}` (admin only; applies from the next run)

## Retention
`app/retention.py` runs hourly inside the backend and on demand with `make retention`. It drops
every day older than `RETENTION_DAYS` (default 7) from ClickHouse's `events` and
`events_minutely`; the day exactly `RETENTION_DAYS` ago is kept, matching what ingest accepts.

- A day is one ClickHouse partition (`PARTITION BY toDate(ts)`), so dropping it
  (`ALTER TABLE … DROP PARTITION`) is instant and frees disk at once. A `DELETE` would rewrite
  data files instead. This is the reason the table is partitioned by day.
- The tables' `TTL` removes the same rows as a safety net, but only when ClickHouse next merges
  those files; the job makes it happen on time.
- New days need nothing: ClickHouse creates a day's partition on its first insert.
- It runs hourly, not daily, because every step is idempotent. A restart or a missed run is
  caught up within the hour, with no "last run" bookkeeping.
- It only drops partitions whose ids match `^\d{8}$` (YYYYMMDD), so it never removes anything else.
- A Postgres advisory lock lets only one backend process run it at a time. It also clears
  `login_failures` rows older than a day.
- Alerts are not removed by retention; they are small and are the record of what happened.

## Dashboard stats
`GET /api/stats?from=&to=` (Bearer token, tenant-scoped; default last 24 h) returns:
- totals (events, failed logins, severity ≥ 7, unique source IPs, open alerts)
- a timeline (15-minute, hourly or daily buckets depending on the range; empty buckets are
  filled with 0, so quiet periods show as quiet instead of disappearing)
- counts by source and by severity band, and the top 10 source IPs and event types

`GET /api/tenants` (admin only) lists tenants for the UI's tenant switcher.
