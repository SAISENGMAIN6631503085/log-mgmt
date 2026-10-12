# Backend (FastAPI)

- `app/main.py` – app + `/health` (returns 503 if Postgres is unreachable)
- `app/config.py` – settings from env vars (documented in `/.env.example`)
- `app/db.py` – asyncpg connection pool
- `app/seed.py` – `make seed` entry point
- `app/migrate.py` + `app/migrations/*.sql` – schema migrations, applied on startup

## Database schema
Migrations run automatically when the backend starts. Each `.sql` file runs once, in name
order, in its own transaction, and is recorded in `schema_migrations`. A Postgres advisory
lock stops two backends from migrating at the same time. To change the schema, add a new
numbered file. Never edit a migration that has already shipped.

| Table | Purpose |
|-------|---------|
| `events` | normalized events, `PARTITION BY RANGE (ts)`, one partition per UTC day (`events_YYYYMMDD`) |
| `users` | login accounts: bcrypt/argon2 hash, `role` admin/viewer, `tenant` |
| `api_keys` | per-tenant ingest keys, stored as SHA-256 hashes |
| `alerts` | alert worker output, indexed for (tenant, rule, src_ip) de-duplication |

Partitions are created from `RETENTION_DAYS` ago up to 7 days ahead on every startup, using
`ensure_event_partition(day)`, which is safe to call repeatedly. There is deliberately
no DEFAULT partition: an event with no partition is rejected rather than silently kept forever.
Ingest must call `ensure_event_partition` for back-dated events.

The schema field `user` is stored as the column `username`, because `USER` is a reserved word in SQL.

- `app/routers/ingest.py` – ingestion endpoints (below)
- `app/auth.py` + `app/routers/auth.py` – login, JWT, tenant scoping
- `app/routers/events.py` – reading events (tenant-scoped)
- `app/api_keys.py` – per-tenant `X-API-Key` auth (keys stored as SHA-256)
- `app/events_store.py` – bulk insert with COPY, timestamp window check

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

## Ingestion endpoints
All three normalize events, store the valid ones, and report the rest:
`{"accepted": n, "rejected_count": m, "rejected": [{"index": i, "error": "..."}]}`.
One bad event never blocks the rest of the batch.

| Endpoint | Auth | Body |
|----------|------|------|
| `POST /api/ingest?source=api` | `X-API-Key` | one JSON event or an array; `source` may be any JSON source (`aws` accepts `{"Records": [...]}`) |
| `POST /api/ingest/file` | `X-API-Key` | multipart: `source` + `file` (.json, .ndjson/.jsonl, .csv, .log/.txt), max 50 MB |
| `POST /api/ingest/syslog` | `X-Ingest-Token` | internal, Vector only; blocked by Caddy from outside |

Rules:
- **The tenant always comes from the API key** (or, for syslog, from the sender IP). A `tenant` field in the body is ignored and kept only in `raw`.
- At most 10,000 events per request; above that the request gets 413.
- Events older than `RETENTION_DAYS` or more than 1 day in the future are rejected, since they could not be stored or would be deleted right away.
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
