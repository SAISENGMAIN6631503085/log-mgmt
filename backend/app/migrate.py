"""Minimal SQL migration runner, run on every startup.

Why not Alembic: we write raw SQL anyway, and a 40-line runner is
easier to explain than autogenerate. Each file in migrations/ is applied once, in name order,
inside a transaction, and recorded in schema_migrations.
"""
from pathlib import Path

import asyncpg

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

# Arbitrary constant. Several backend processes may start at once; the advisory lock
# makes the others wait instead of applying the same migration twice.
_LOCK_ID = 7_340_001


async def run_migrations(conn: asyncpg.Connection) -> list[str]:
    """Apply pending migrations; returns the names applied this run."""
    applied_now: list[str] = []
    await conn.execute("SELECT pg_advisory_lock($1)", _LOCK_ID)
    try:
        await conn.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                   name text PRIMARY KEY,
                   applied_at timestamptz NOT NULL DEFAULT now())"""
        )
        done = {r["name"] for r in await conn.fetch("SELECT name FROM schema_migrations")}
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if path.name in done:
                continue
            # One transaction per file: a broken migration leaves the DB unchanged.
            async with conn.transaction():
                await conn.execute(path.read_text())
                await conn.execute("INSERT INTO schema_migrations (name) VALUES ($1)", path.name)
            applied_now.append(path.name)
    finally:
        await conn.execute("SELECT pg_advisory_unlock($1)", _LOCK_ID)
    return applied_now
