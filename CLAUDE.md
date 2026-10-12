# Project: Mini Log Management System (Intern Assignment)

A demo multi-tenant log management / SIEM-lite system. It ingests logs from several sources,
normalizes them into a common schema, stores and searches them, shows a dashboard, and fires alerts.
It must run in two modes: **Appliance** (single VM, Docker Compose) and **SaaS** (public cloud VM, HTTPS URL).

Deadline: ~2026-10-22. Prefer simple, working, well-documented code over clever code.
The author must be able to explain every design decision in an interview, so keep the code readable
and add short comments explaining *why*, not *what*.

## Tech stack (do not add new major dependencies without asking)
- Collector: **Vector** — listens on syslog UDP/TCP 514, parses, and forwards JSON to the backend over HTTP
- Backend: **Python 3.12 + FastAPI**, SQLAlchemy Core or asyncpg, Pydantic v2
- Storage: **PostgreSQL 16** — `events` table partitioned by day (RANGE on `ts`), JSONB `raw`, GIN index on `raw` and `_tags`
  - (If switching to ClickHouse for events: keep Postgres for users/rules/alerts; use MergeTree, ORDER BY (tenant, ts), TTL 7+ days)
- Frontend: **React + Vite + TypeScript**, Recharts, plain CSS or Tailwind
- Reverse proxy / TLS: **Caddy** (Let's Encrypt in SaaS mode, `tls internal` self-signed in appliance mode)
- Everything runs via **docker-compose.yml**; all images must support linux/arm64 AND linux/amd64
- Tests: **pytest** (backend), optional Vitest (frontend)
- Everything must be free / open-source

## Repository layout (required by the assignment)
```
/backend/      FastAPI app (api, auth, normalizers, alert worker, retention job) + README
/frontend/     React app + README
/ingest/       Vector config + README
/samples/      sample log files, send_syslog.sh, post_logs.py, simulator
/tests/        pytest tests (at least: normalizers, tenant isolation, alert rule)
/docs/         architecture.md, setup_appliance.md, setup_saas.md
docker-compose.yml, .env.example, Makefile, Caddyfile, postman_collection.json
```

## Common schema (every event is normalized to this before storage)
`@timestamp` (RFC3339, stored as `ts timestamptz`), `tenant`, `source`
(firewall|network|api|crowdstrike|aws|m365|ad), `vendor`, `product`, `event_type`, `event_subtype`,
`severity` (0-10), `action` (allow|deny|create|delete|login|logout|alert|quarantine), `src_ip`, `src_port`,
`dst_ip`, `dst_port`, `protocol`, `user`, `host`, `process`, `url`, `http_method`, `status_code`,
`rule_name`, `rule_id`, `cloud_account_id`, `cloud_region`, `cloud_service`, `raw` (original), `_tags` (text[])

## Normalization rules
- One mapper function per source in `backend/app/normalizers/<source>.py`, each pure and unit-tested
- Always keep the original payload in `raw`
- Unify field aliases: `ip`/`src` → `src_ip`, `dst` → `dst_ip`, `spt` → `src_port`, `dpt` → `dst_port`, `proto` → `protocol`
- Syslog: parse `<PRI>`, timestamp, hostname, then `key=value` pairs. Syslog severity (PRI % 8) maps to 0-10.
  Syslog has no year → assume current year, UTC. Syslog has no tenant → map by sender IP via config, else `DEFAULT_TENANT`.
- AD 4625 / M365 failed status / api `*_failed` → `action=login`, `_tags` include `auth_failure`

## Ingestion endpoints
- `POST /api/ingest` — single JSON event or array (auth: per-tenant API key header `X-API-Key`)
- `POST /api/ingest/file` — upload JSON / NDJSON / CSV batch (AWS, M365, AD, CrowdStrike samples)
- `POST /api/ingest/syslog` — internal, called only by Vector
- At least 4 real working sources: syslog (via Vector), HTTP JSON, file upload, simulator script

## Security (critical — reviewers will test this)
- JWT login; claims: `sub`, `role` (admin|viewer), `tenant`
- **Tenant filter is always applied server-side from the JWT**, never trusted from query/header for viewers
- Admin may pass `?tenant=` to switch tenants; viewer requests for another tenant → 403
- Passwords hashed with bcrypt/argon2; secrets only from env vars; never commit `.env`
- Seed users: admin, viewerA (tenant demoA), viewerB (tenant demoB)

## Alerting
- Background worker runs every 60s
- Rule 1: >= 5 failed logins from the same `src_ip` (per tenant) within 5 minutes
- Store in `alerts` table, show on Alerts page, POST JSON to `ALERT_WEBHOOK_URL` if set
- De-duplicate: don't re-alert the same (tenant, rule, src_ip) within the window

## Retention
- Daily partitions created ahead of time; job drops partitions older than `RETENTION_DAYS` (default 7)

## Conventions
- Config via env vars only; every var documented in `.env.example`
- `make up`, `make down`, `make seed`, `make test`, `make logs` must work
- Small commits with clear messages; run `make test` before committing
- When finishing a feature, update the relevant README/docs in the same change
- Do not delete or rewrite tests to make them pass
