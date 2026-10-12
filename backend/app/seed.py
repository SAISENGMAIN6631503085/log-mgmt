"""Seeds demo data. Users/tenants are added once the auth schema exists; for now it only checks the DB."""
import asyncio

from . import db


async def main() -> None:
    await db.connect()
    try:
        if not await db.ping():
            raise SystemExit("database not reachable")
        print("seed: database reachable (no schema to seed yet)")
    finally:
        await db.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
