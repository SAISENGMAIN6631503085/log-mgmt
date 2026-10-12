# Backend (FastAPI)

- `app/main.py` – app + `/health` (returns 503 if Postgres is unreachable)
- `app/config.py` – settings from env vars (documented in `/.env.example`)
- `app/db.py` – asyncpg connection pool
- `app/seed.py` – `make seed` entry point

Tests live in `/tests` at the repo root; run them with `make test`.
