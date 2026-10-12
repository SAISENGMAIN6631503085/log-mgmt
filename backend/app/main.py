from contextlib import asynccontextmanager

from fastapi import FastAPI, Response

from . import db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    yield
    await db.disconnect()


app = FastAPI(title="Mini Log Management", lifespan=lifespan)


@app.get("/health")
async def health(response: Response) -> dict:
    # Reports the DB too, so "healthy" means the app can actually serve requests.
    # 503 lets Docker/Caddy/uptime checks treat a DB outage as unhealthy.
    db_ok = await db.ping()
    if not db_ok:
        response.status_code = 503
    return {"status": "ok" if db_ok else "degraded", "database": "ok" if db_ok else "down"}
