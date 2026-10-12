"""Ingestion endpoints: HTTP JSON, file upload, and syslog forwarded by Vector."""
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Body, Depends, File, Form, Header, HTTPException, Query, UploadFile
from pydantic import BaseModel, ValidationError

from .. import db
from ..api_keys import tenant_from_api_key
from ..config import settings
from ..events_store import check_ts_window, insert_events
from ..ingest_parsing import classify_syslog, parse_upload, split_payloads
from ..normalizers import NORMALIZERS, normalize
from ..normalizers.syslog import parse_tenant_map, tenant_for_sender

router = APIRouter(prefix="/api/ingest", tags=["ingest"])

MAX_EVENTS_PER_REQUEST = 10_000
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_ERRORS_RETURNED = 100  # keep responses small when a whole file is bad

# Parsed once at import; changing the map needs a restart, like every other env var.
_TENANT_MAP = parse_tenant_map(settings.syslog_tenant_map)


class Rejected(BaseModel):
    index: int
    error: str


class IngestResult(BaseModel):
    accepted: int
    duplicates: int  # valid events that were already stored (e.g. the same file uploaded twice)
    rejected_count: int
    rejected: list[Rejected]


def _error_text(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        err = exc.errors()[0]
        return f"{'.'.join(map(str, err['loc']))}: {err['msg']}"
    return str(exc)[:300]


async def _process(items: list[tuple[str, Any, str]]) -> IngestResult:
    """Normalize (source, payload, tenant) items, store the good ones, report the bad ones.

    Partial success on purpose: one malformed line in a 10k-line file shouldn't block the
    other 9,999. The caller gets each rejected index and why.
    """
    if len(items) > MAX_EVENTS_PER_REQUEST:
        raise HTTPException(413, f"too many events: {len(items)} > {MAX_EVENTS_PER_REQUEST}; split the batch")
    now = datetime.now(timezone.utc)
    events, rejected = [], []
    for i, (source, payload, tenant) in enumerate(items):
        try:
            ev = normalize(source, payload, tenant, now=now)
            if err := check_ts_window(ev.ts, settings.retention_days, now):
                raise ValueError(err)
            events.append(ev)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:  # ValidationError is a ValueError
            rejected.append(Rejected(index=i, error=_error_text(exc)))

    async with db.pool.acquire() as conn:
        accepted = await insert_events(conn, events)
    return IngestResult(accepted=accepted, duplicates=len(events) - accepted, rejected_count=len(rejected), rejected=rejected[:MAX_ERRORS_RETURNED])


def _check_source(source: str) -> None:
    if source not in NORMALIZERS:
        raise HTTPException(400, f"unknown source {source!r}; expected one of {sorted(NORMALIZERS)}")


@router.post("", response_model=IngestResult)
async def ingest_json(
    body: Any = Body(..., description="One event, an array of events, or a CloudTrail Records file"),
    source: str = Query("api", description="Which normalizer to use"),
    tenant: str = Depends(tenant_from_api_key),
) -> IngestResult:
    _check_source(source)
    try:
        payloads = split_payloads(source, body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return await _process([(source, p, tenant) for p in payloads])


@router.post("/file", response_model=IngestResult)
async def ingest_file(
    file: UploadFile = File(...),
    source: str = Form(..., description="aws, m365, ad, crowdstrike, api, firewall or network"),
    tenant: str = Depends(tenant_from_api_key),
) -> IngestResult:
    _check_source(source)
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    try:
        payloads = parse_upload(file.filename or "", content, source)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, f"could not parse file: {_error_text(exc)}") from None
    return await _process([(source, p, tenant) for p in payloads])


class SyslogRecord(BaseModel):
    message: str
    host: str | None = None  # sender IP, added by Vector's socket source


@router.post("/syslog", response_model=IngestResult, include_in_schema=False)
async def ingest_syslog(
    records: list[SyslogRecord],
    x_ingest_token: str | None = Header(default=None),
) -> IngestResult:
    """Internal: only Vector calls this. Caddy also refuses it from outside (see Caddyfile);
    the token is a second lock in case the backend is ever exposed directly."""
    expected = settings.syslog_ingest_token
    # compare_digest: constant-time, so the token can't be guessed byte by byte from timings.
    if not expected or not x_ingest_token or not secrets.compare_digest(x_ingest_token, expected):
        raise HTTPException(401, "invalid ingest token")
    items = []
    for r in records:
        line = r.message.strip()
        tenant = tenant_for_sender(r.host, _TENANT_MAP, settings.default_tenant)
        items.append((classify_syslog(line), line, tenant))
    return await _process(items)
