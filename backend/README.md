# Backend (FastAPI)

Login, search, the dashboard, alerts, API keys and retention. Logs are **received** by the Go
ingest service (`/ingest`, see [ingest/README.md](../ingest/README.md)), which writes them to
ClickHouse; this backend reads them.

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
- Memory is capped in `clickhouse/config.d/small-server.xml` (900 MB for the server, of which
  ~240 MB is ClickHouse's own program code; 400 MB per query) and tuned with ClickHouse's low-memory settings: small background pools, one thread per
  query, no parallel parsing. Measured: about 250–350 MB idle and under 400 MB during the whole test
  suite, so it fits a 2 GB VM. On a bigger appliance, raise the limits or delete that file.

The schema field `user` is stored as the column `username`, because `USER` is a reserved word in
SQL; `_tags` is stored as `tags`.

- `app/auth.py` + `app/routers/auth.py` – login, JWT, tenant scoping
- `app/routers/events.py` – event search and single event (tenant-scoped)
- `app/search.py` – builds the ClickHouse search query (pure, unit-tested)
- `app/ch_stats.py` – the dashboard numbers, from ClickHouse
- `app/alerting.py` + `app/routers/alerts.py` – alert worker and alerts API
- `app/retention.py` – drops old days of events (hourly, and `make retention`)
- `app/api_keys.py` + `app/routers/keys.py` – per-tenant ingest keys (stored as SHA-256), created and revoked here
- `app/schema.py` – allowed sources and actions, for validating filters
- `app/clickhouse.py` – the small ClickHouse HTTP client

Tests live in `/tests` at the repo root; run them with `make test`.

## How each feature uses ClickHouse
- **Ingest** is the Go service: it stores each batch in ClickHouse, skipping duplicates
  (see `ingest/README.md`). The backend creates the tables at startup (`app/ch_schema.py`).
- **Dashboard** (`/api/stats`, `app/ch_stats.py`): counts, timeline and breakdowns read
  `events_minutely`, so they cost the same at any volume (precision: one minute). Top lists read
  the events table. The response says which engine answered and how long it took (`engine`),
  shown on the Overview.
- **Search** (`/api/events`, `/api/events/{id}`): keyset paging on `(ts, id)`, see below.
- **Alerts**: detection counts events in each window with a window function
  (`RANGE BETWEEN <window> PRECEDING`). Per-tenant rule settings are in Postgres and applied in Python.
- **Retention** drops whole days (`ALTER TABLE … DROP PARTITION`), see below.

Tests of search, the dashboard and alerts write their events straight into ClickHouse
(`store_events` in `tests/conftest.py`); tests of ingest send logs to the Go service. Their ClickHouse data is deleted in one statement at the end of the run: a ClickHouse `DELETE`
rewrites files in the background, and one per test piled up.

## Country of an IP (`app/geoip.py`)
Countries are added to events at ingest (Go service). The backend also reads the same DB-IP Lite
file (`fetch_geoip.py` downloads it at build time) to label the IP in each alert and to tell the
website whether country data is available (`/api/info`).

## API keys
Logs are sent to the Go ingest service with a per-tenant `X-API-Key` (endpoints and rules in
`ingest/README.md`). The keys themselves live in Postgres and are managed here.

API keys are managed by admins, per tenant (`?tenant=`, same rule as every read endpoint):

| Endpoint | What it does |
|----------|--------------|
| `GET /api/keys` | List the tenant's keys: name, prefix (`lm_xxxxx…`), created, revoked. Never the key or its hash. |
| `POST /api/keys` `{"name": "shop website"}` | Create a key. The full key is in this response **only**; it's stored as a SHA-256 hash. |
| `POST /api/keys/{id}/revoke` | Revoke it: it stops working at once. The row stays (audit trail). Another tenant's key → 404. |

Demo keys come from `SEED_API_KEYS` and are created by `make seed`.

## Login and tenant isolation
`POST /api/auth/login` takes `{"username", "password"}` and returns a JWT. Send it as
`Authorization: Bearer <token>`. The token's claims are `sub`, `role` (admin|viewer) and `tenant`.
`GET /api/auth/me` shows the current claims.

**Tenants** (`routers/tenants.py`, admin only, 403 for viewers): onboarding a customer from the website.
- `GET /api/admin/tenants`: every tenant with its viewers and number of active API keys.
- `POST /api/admin/tenants {"name": "acme"}`: a tenant has no table of its own (it exists once it has a
  user or an API key), so this creates its **first API key** and returns it once. Names are letters,
  digits, `-` and `_`, starting with a letter; a name that differs only in letter case from an existing
  one is refused (409), so `demoa` can't sit next to `demoA`.
- `POST /api/admin/tenants/{tenant}/viewers {"username", "password"}`: a viewer for that tenant only
  (password at least 12 characters, hashed like the others; usernames unique ignoring case; 404 for an
  unknown tenant). The viewer's JWT carries the tenant, so `resolve_tenant` keeps them inside it.
- `make seed` still sets up the starting demo (admin, viewerA, viewerB, demoA, demoB, known keys);
  this page is for adding more afterwards. Not built: removing a viewer or resetting a password. A
  removed viewer's token would also stay valid until it expires (8 hours), so removal would need a
  per-request user check or a token block list.

**Admin default tenant** (migration 008): `PUT /api/auth/default-tenant {"tenant": "demoB"}` sets the
tenant an admin sees after signing in (the website's "Make demoB my default"). It's admin only (403
for viewers), only accepts tenants that exist (404 otherwise), and returns a fresh token carrying
the new tenant so it applies at once. For an admin the token's `tenant` is just the one shown when
no `?tenant=` is passed, so changing it grants nothing new. A viewer's tenant is the security
boundary and never changes: `default_tenant` is ignored for viewers even if set in the database.

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
  events *arrived* in the last 10 minutes (`ingested_at`), then slides the rule's window over
  their matching events by `ts` (ClickHouse `count() OVER (... RANGE BETWEEN <window> PRECEDING ...)`).
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

7 days is the assignment's minimum. A real deployment sets it from its legal duties: in Thailand,
the Computer Crime Act (B.E. 2550, s. 26) requires service providers to keep traffic data for at
least 90 days, while the PDPA says not to keep personal data longer than needed. Either way it's
one setting, `RETENTION_DAYS`.

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
