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
