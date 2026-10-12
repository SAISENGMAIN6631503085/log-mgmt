import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response

from . import db
from .alerting import worker_loop
from .auth import check_jwt_secret
from .routers import alerts, auth, events, ingest

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    check_jwt_secret()  # refuse to start rather than run with forgeable tokens
    await db.connect()
    # In-process background task: no extra container or queue for a once-a-minute job.
    worker = asyncio.create_task(worker_loop())
    yield
    worker.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await worker
    await db.disconnect()


app = FastAPI(title="Mini Log Management", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(ingest.router)
app.include_router(events.router)
app.include_router(alerts.router)


@app.get("/health")
async def health(response: Response) -> dict:
    # Reports the DB too, so "healthy" means the app can actually serve requests.
    # 503 lets Docker/Caddy/uptime checks treat a DB outage as unhealthy.
    db_ok = await db.ping()
    if not db_ok:
        response.status_code = 503
    return {"status": "ok" if db_ok else "degraded", "database": "ok" if db_ok else "down"}
