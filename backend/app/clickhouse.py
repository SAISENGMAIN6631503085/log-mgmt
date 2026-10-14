"""A small ClickHouse client over its HTTP interface (port 8123), using httpx (already a dependency).

Values never go into the SQL text: queries use ClickHouse's typed placeholders, e.g.
`WHERE tenant = {tenant:String}`, and the values travel separately as `param_tenant=...`,
so search input can't inject SQL. Same rule as the asyncpg ($1) queries on Postgres.
"""
import asyncio
import json
import logging
import weakref
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import settings

log = logging.getLogger("clickhouse")


def _param(value: Any) -> str:
    """A Python value in the text form ClickHouse expects for a query parameter."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    if isinstance(value, (list, tuple)):
        # Array literal: ['a','b'] with quotes and backslashes escaped.
        return "[" + ",".join(_quote(v) for v in value) + "]"
    if value is None:
        return "\\N"
    return str(value)


def _quote(v: Any) -> str:
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


class ClickHouse:
    def __init__(self) -> None:
        # One HTTP client per event loop: a client belongs to the loop that made it, and the app,
        # scripts and tests can run several loops (even on several threads at once). Weak keys:
        # a finished loop's entry goes away by itself.
        self._clients: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, httpx.AsyncClient] = \
            weakref.WeakKeyDictionary()

    def _client(self) -> httpx.AsyncClient:
        """This event loop's client, created on first use."""
        loop = asyncio.get_running_loop()
        if loop not in self._clients:
            self._clients[loop] = httpx.AsyncClient(
                base_url=settings.clickhouse_url,
                auth=(settings.clickhouse_user, settings.clickhouse_password),
                params={"database": settings.clickhouse_db},
                timeout=30,
            )
        return self._clients[loop]

    async def connect(self) -> None:
        self._client()

    async def close(self) -> None:
        """Close this event loop's client (others belong to other loops)."""
        client = self._clients.pop(asyncio.get_running_loop(), None)
        if client:
            await client.aclose()

    async def _post(self, sql: str, params: dict[str, Any] | None, body: bytes | None = None, **settings_) -> str:
        query = {"query": sql, **{f"param_{k}": _param(v) for k, v in (params or {}).items()}, **settings_}
        r = await self._client().post("/", params=query, content=body)
        if r.status_code != 200:
            raise RuntimeError(f"ClickHouse error {r.status_code}: {r.text[:500]}")
        return r.text

    async def ping(self) -> bool:
        """True if ClickHouse answers a trivial query (/ping refuses the client's ?database= param)."""
        try:
            return (await self._client().post("/", params={"query": "SELECT 1"}, timeout=3)).status_code == 200
        except httpx.HTTPError:
            return False

    async def command(self, sql: str, params: dict[str, Any] | None = None) -> None:
        """DDL and other statements without a result."""
        await self._post(sql, params)

    async def query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Rows as dicts. 64-bit numbers come back as numbers (not strings)."""
        text = await self._post(sql + "\nFORMAT JSONEachRow", params, output_format_json_quote_64bit_integers=0)
        return [json.loads(line) for line in text.splitlines() if line]

    async def insert(self, table: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        body = "\n".join(json.dumps(r, default=str) for r in rows).encode()
        await self._post(f"INSERT INTO {table} FORMAT JSONEachRow", None, body, date_time_input_format="best_effort")


ch = ClickHouse()
