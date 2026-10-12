"""`make seed`: create demo data. Safe to run repeatedly (everything is upserted)."""
import asyncio

from . import db
from .api_keys import create_key
from .auth import hash_password
from .config import settings


async def seed_api_keys(conn) -> None:
    # Keys come from SEED_API_KEYS in .env so the demo (Postman, scripts) can use known values.
    for item in filter(None, (s.strip() for s in settings.seed_api_keys.split(","))):
        tenant, _, key = item.partition("=")
        await create_key(conn, tenant.strip(), "seed", key.strip())
        print(f"seed: api key for tenant {tenant.strip()!r} ready ({key.strip()[:8]}...)")


# (username, role, tenant, password setting). The admin's tenant is only its default view.
DEMO_USERS = [
    ("admin", "admin", "demoA", "seed_admin_password"),
    ("viewerA", "viewer", "demoA", "seed_viewer_password"),
    ("viewerB", "viewer", "demoB", "seed_viewer_password"),
]


async def seed_users(conn) -> None:
    for username, role, tenant, pw_setting in DEMO_USERS:
        password = getattr(settings, pw_setting)
        if not password:
            print(f"seed: skipping {username}: {pw_setting.upper()} is not set")
            continue
        # Upsert so changing the password in .env and re-running `make seed` updates it.
        await conn.execute(
            """INSERT INTO users (username, password_hash, role, tenant) VALUES ($1, $2, $3, $4)
               ON CONFLICT (username) DO UPDATE
               SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role, tenant = EXCLUDED.tenant""",
            username, hash_password(password), role, tenant,
        )
        print(f"seed: user {username!r} ({role}, tenant {tenant}) ready")


async def main() -> None:
    await db.connect()
    try:
        async with db.pool.acquire() as conn:
            await seed_users(conn)
            await seed_api_keys(conn)
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
