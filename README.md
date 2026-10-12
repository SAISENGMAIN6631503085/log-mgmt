# Mini Log Management System

Multi-tenant log ingestion, search, dashboard and alerting. See `CLAUDE.md` for the full spec.

## Quick start (appliance mode)
```
make up        # builds and starts everything, creates .env from .env.example on first run
open https://localhost   # self-signed cert from Caddy's internal CA; accept the warning
```
`make up` finishes by printing `https://localhost/health`, e.g. `{"status":"ok","database":"ok"}`.

| Target      | What it does |
|-------------|--------------|
| `make up`   | build + start all services, wait until healthy, check `/health` |
| `make down` | stop everything (data volumes are kept) |
| `make seed` | load demo data |
| `make test` | run pytest from `/tests` inside the backend image |
| `make logs` | follow logs from all services |

## Services
| Service  | Role | Exposed |
|----------|------|---------|
| caddy    | TLS + reverse proxy: `/api/*`, `/health` → backend, everything else → frontend | 80, 443 |
| backend  | FastAPI | internal :8000 |
| frontend | React SPA (built by Vite, served as static files) | internal :80 |
| postgres | PostgreSQL 16 | internal only |
| vector   | syslog receiver → backend | 514/udp, 514/tcp |
