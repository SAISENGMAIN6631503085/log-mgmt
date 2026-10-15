# Project: Mini Log Management System (Intern Assignment)

A demo multi-tenant log management / SIEM-lite system. It ingests logs from several sources,
normalizes them into a common schema, stores and searches them, shows a dashboard, and fires alerts.
It must run in two modes: **Appliance** (single VM, Docker Compose) and **SaaS** (public cloud VM, HTTPS URL).

Deadline: ~2026-10-22. Prefer simple, working, well-documented code over clever code.
The author must be able to explain every design decision in an interview, so keep the code readable
and add short comments explaining *why*, not *what*.

## Tech stack (do not add new major dependencies without asking)
- Collector: **Vector** — listens on syslog UDP/TCP 514 and forwards raw lines as JSON to the ingest service over HTTP
- Ingest service: **Go 1.23** (net/http, pgx, golang-jwt, maxminddb) — receives every log, normalizes, enriches, dedups, writes to ClickHouse
- Backend: **Python 3.12 + FastAPI**, asyncpg, Pydantic v2 — login, search, dashboard, alerts, API keys, rules, retention
- Storage: **ClickHouse 24.8** for events (ReplacingMergeTree, PARTITION BY day, ORDER BY (tenant, ts, fingerprint), TTL = RETENTION_DAYS);
  **PostgreSQL 16** for users, api_keys, alerts, rule_settings, login_failures
- Frontend: **React + Vite + TypeScript**, Recharts, plain CSS or Tailwind
- Reverse proxy / TLS: **Caddy** (Let's Encrypt in SaaS mode, `tls internal` self-signed in appliance mode)
- Everything runs via **docker-compose.yml**; all images must support linux/arm64 AND linux/amd64
- Tests: **pytest** (backend + end to end), **go test** (ingest), optional Vitest (frontend)
- Everything must be free / open-source

## Repository layout (required by the assignment)
```
/backend/      FastAPI app (api, auth, search, stats, alert worker, retention job) + README
/frontend/     React app + README
/ingest/       Go ingest service (normalizers, store, endpoints) + Vector config + README
/samples/      sample log files, send_syslog.sh, post_logs.py, simulator
/tests/        pytest tests (at least: tenant isolation, alert rule, ingest end to end); normalizer tests are Go, in /ingest
/docs/         architecture.md, setup_appliance.md, setup_saas.md
docker-compose.yml, .env.example, Makefile, Caddyfile, postman_collection.json
```

## Common schema (every event is normalized to this before storage)
`@timestamp` (RFC3339, stored as ClickHouse `ts DateTime64(3, 'UTC')`), `tenant`, `source`
(firewall|network|api|crowdstrike|aws|m365|ad), `vendor`, `product`, `event_type`, `event_subtype`,
`severity` (0-10), `action` (allow|deny|create|delete|login|logout|alert|quarantine), `src_ip`, `src_port`,
`dst_ip`, `dst_port`, `protocol`, `user`, `host`, `process`, `url`, `http_method`, `status_code`,
`rule_name`, `rule_id`, `cloud_account_id`, `cloud_region`, `cloud_service`, `raw` (original), `_tags` (stored as `tags`),
plus `src_country` (GeoIP enrichment at ingest). `user` is stored as `username` (reserved word).
Duplicates: same fingerprint (sha256 of tenant + source + raw) at the same `ts`; for `time_adjusted` events the fingerprint alone.

## Normalization rules
- One mapper function per source in `ingest/normalize/<source>.go`, each pure and unit-tested
- Always keep the original payload in `raw`
- Unify field aliases: `ip`/`src` → `src_ip`, `dst` → `dst_ip`, `spt` → `src_port`, `dpt` → `dst_port`, `proto` → `protocol`
- Syslog: parse `<PRI>`, timestamp, hostname, then `key=value` pairs. Syslog severity (PRI % 8) maps to 0-10.
  Syslog has no year → assume current year, UTC. Syslog has no tenant → map by sender IP via config, else `DEFAULT_TENANT`.
- AD 4625 / M365 failed status / api `*_failed` → `action=login`, `_tags` include `auth_failure`

## Ingestion endpoints (Go ingest service; Caddy routes `/ingest` and `/api/ingest/*` to it)
- `POST /api/ingest` — single JSON event or array (auth: per-tenant API key header `X-API-Key`)
- `POST /api/ingest/file` — upload JSON / NDJSON / CSV batch (AWS, M365, AD, CrowdStrike samples)
- `POST /api/ingest/syslog` — internal, called only by Vector
- At least 4 real working sources: syslog (via Vector), HTTP JSON, file upload, simulator script

## Security (critical — reviewers will test this)
- JWT login; claims: `sub`, `role` (admin|viewer), `tenant`
- **Tenant filter is always applied server-side from the JWT**, never trusted from query/header for viewers
- Admin may pass `?tenant=` to switch tenants; viewer requests for another tenant → 403
- Admins can choose their default tenant (`PUT /api/auth/default-tenant`, `users.default_tenant`); viewers can't
- Passwords hashed with bcrypt/argon2; secrets only from env vars; never commit `.env`
- Seed users: admin, viewerA (tenant demoA), viewerB (tenant demoB)
- Ingest API keys stored as SHA-256 hashes, shown once, revocable; sign-in throttling (5 failures per
  username / 20 per IP in 5 min → 429)
- Syslog port 514 is closed on the live (SaaS) server on purpose (`SYSLOG_BIND=127.0.0.1`)

## Alerting
- Background worker (backend) runs every 60s, reading events from ClickHouse by event time
- 3 rules of one shape (`RULES` in `backend/app/alerting.py`): brute-force login (>= 5 `auth_failure`
  from one `src_ip` in 5 min), firewall scan (>= 20 blocked from one `src_ip`), malware (CrowdStrike
  severity >= 7 per `host`); admins can turn each off or change its threshold per tenant (`rule_settings`)
- Store in `alerts` table, show on Alerts page, POST JSON to `ALERT_WEBHOOK_URL` if set (plain JSON)
- De-duplicate: don't re-alert the same (tenant, rule, src_ip or host) within the window

## Retention
- ClickHouse partitions by day (created on first insert); the hourly job drops days older than
  `RETENTION_DAYS` (default 7, the assignment's minimum; Thai law needs >= 90 for real service providers);
  the table TTL is a safety net

## Conventions
- Config via env vars only; every var documented in `.env.example`
- `make up`, `make down`, `make seed`, `make test`, `make logs` must work
- Small commits with clear messages; run `make test` before committing
- When finishing a feature, update the relevant README/docs in the same change
- Do not delete or rewrite tests to make them pass
- Pushing to `main` runs CI and **auto-deploys the live SaaS site** (https://14.207.143.101.sslip.io);
  the user commits and pushes themselves
- Tests run inside containers: rebuild the changed image (`docker compose up -d --build <service>`)
  before `make test`
