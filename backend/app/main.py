import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response

from . import db
from .alerting import worker_loop
from .auth import check_jwt_secret
from .clickhouse import ch
from .retention import retention_loop
from .routers import alerts, auth, events, keys, rules, stats

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
# httpx logs every request (each ClickHouse query and webhook) at INFO: too noisy.
logging.getLogger("httpx").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    check_jwt_secret()  # refuse to start rather than run with forgeable tokens
    await db.connect()
    # In-process background tasks: no extra container or queue for periodic jobs.
    tasks = [asyncio.create_task(worker_loop()), asyncio.create_task(retention_loop())]
    yield
    for t in tasks:
        t.cancel()
    # Bounded wait: a stuck job must not block shutdown (the pool close below is bounded too).
    await asyncio.wait(tasks, timeout=10)
    await db.disconnect()


app = FastAPI(title="Mini Log Management", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(keys.router)
app.include_router(rules.router)
# Logs arrive at the Go ingest service (/ingest, /api/ingest/*), not here; Caddy routes them.


@app.get("/health")
async def health(response: Response) -> dict:
    # Reports both databases, so "healthy" means the app can actually serve requests: Postgres
    # (users, alerts) and ClickHouse (the logs). 503 lets Docker/Caddy/uptime checks treat an
    # outage of either as unhealthy.
    db_ok, events_ok = await db.ping(), await ch.ping()
    if not (db_ok and events_ok):
        response.status_code = 503
    return {"status": "ok" if db_ok and events_ok else "degraded",
            "database": "ok" if db_ok else "down", "event_store": "ok" if events_ok else "down"}
