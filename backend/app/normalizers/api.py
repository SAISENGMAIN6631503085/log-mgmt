"""Application/API JSON events (our own HTTP ingest format) -> Event."""
from datetime import datetime, timezone
from typing import Any

from .common import AUTH_FAILURE, Event, clean_ip, parse_ts, to_int, to_port, unify_aliases

# CLAUDE.md: api `*_failed` -> login + auth_failure. Restricted to auth-related names so that
# e.g. "payment_failed" doesn't count toward the brute-force login alert.
_AUTH_WORDS = ("login", "logon", "signin", "sign_in", "auth", "mfa", "password")
_ACTIONS = {"allow", "deny", "create", "delete", "login", "logout", "alert", "quarantine"}


def _is_auth(event_type: str) -> bool:
    return any(w in event_type for w in _AUTH_WORDS)


def normalize(payload: dict[str, Any], tenant: str, *, now: datetime | None = None) -> Event:
    d = unify_aliases(payload)
    event_type = str(d.get("event_type") or "").lower() or None
    status = to_int(d.get("status_code", d.get("status")))

    tags: list[str] = []
    action = d.get("action") if d.get("action") in _ACTIONS else None
    if event_type and _is_auth(event_type):
        action = action or "login"
        if event_type.endswith("_failed"):
            tags.append(AUTH_FAILURE)
    elif event_type and event_type.startswith("logout"):
        action = action or "logout"

    severity = to_int(d.get("severity"))
    if severity is None or not 0 <= severity <= 10:
        # Derive from outcome when the app didn't send one.
        if status is not None and status >= 500:
            severity = 6
        elif tags:
            severity = 5
        elif status is not None and status >= 400:
            severity = 4
        else:
            severity = 2

    ts_value = d.get("@timestamp") or d.get("timestamp") or d.get("time")
    return Event(
        # Apps sometimes omit the time; receipt time is the best we have.
        ts=parse_ts(ts_value) if ts_value else (now or datetime.now(timezone.utc)),
        # Tenant comes from the API key, never from the body: a client must not be able
        # to write into another tenant by putting "tenant": "x" in the JSON.
        tenant=tenant,
        source="api",
        vendor=d.get("vendor") or "custom",
        product=d.get("service") or d.get("product"),
        event_type=event_type,
        event_subtype=d.get("event_subtype") or d.get("reason"),
        severity=severity,
        action=action,
        src_ip=clean_ip(d.get("src_ip")),
        src_port=to_port(d.get("src_port")),
        dst_ip=clean_ip(d.get("dst_ip")),
        dst_port=to_port(d.get("dst_port")),
        user=d.get("user") or d.get("username"),
        host=d.get("host"),
        process=d.get("process"),
        url=d.get("url") or d.get("path"),
        http_method=(d.get("http_method") or d.get("method") or "").upper() or None,
        status_code=status,
        raw=payload,
        tags=tags,
    )
