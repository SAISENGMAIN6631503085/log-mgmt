"""`make seed`: create demo data. Safe to run repeatedly (everything is upserted)."""
import asyncio

from . import db
from .api_keys import create_key
from .config import settings


async def seed_api_keys(conn) -> None:
    # Keys come from SEED_API_KEYS in .env so the demo (Postman, scripts) can use known values.
    for item in filter(None, (s.strip() for s in settings.seed_api_keys.split(","))):
        tenant, _, key = item.partition("=")
        await create_key(conn, tenant.strip(), "seed", key.strip())
        print(f"seed: api key for tenant {tenant.strip()!r} ready ({key.strip()[:8]}...)")


async def main() -> None:
    await db.connect()
    try:
        async with db.pool.acquire() as conn:
            await seed_api_keys(conn)
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
