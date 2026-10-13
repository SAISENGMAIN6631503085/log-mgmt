"""Active Directory / Windows Security events (CSV export rows or JSON) -> Event."""
from typing import Any

from .common import AUTH_FAILURE, Event, blank_to_none, clean_ip, flat_time, parse_ts, to_int, to_port

# EventID -> (event_type, action, severity, tags). Only the IDs a SOC usually watches.
_EVENTS: dict[int, tuple[str, str | None, int, list[str]]] = {
    4624: ("logon_success", "login", 2, []),
    4625: ("logon_failure", "login", 5, [AUTH_FAILURE]),
    4634: ("logoff", "logout", 1, []),
    4720: ("user_created", "create", 4, []),
    4726: ("user_deleted", "delete", 5, []),
    4740: ("account_lockout", "alert", 6, ["account_lockout"]),
}


def _from_flat(d: dict[str, Any]) -> dict[str, Any]:
    """The assignment's flat AD sample ({"event_id": 4625, "user": ..., "ip": ...}), reshaped as an export row."""
    return {
        "TimeCreated": flat_time(d),
        "EventID": d.get("event_id"),
        "TargetUserName": d.get("user"),
        "Computer": d.get("host"),
        "IpAddress": d.get("src_ip") or d.get("ip"),
        "IpPort": d.get("src_port"),
        "LogonType": d.get("logon_type"),
        "_event_type": d.get("event_type"),
    }


def normalize(row: dict[str, Any], tenant: str, **_) -> Event:
    original = row
    if "EventID" not in row and "TimeCreated" not in row:
        row = _from_flat(row)
    event_id = to_int(row.get("EventID"))
    # Unknown IDs keep the sender's own event_type name if it gave one.
    fallback = row.get("_event_type") or f"event_{event_id}"
    event_type, action, severity, tags = _EVENTS.get(event_id, (fallback, None, 2, []))
    return Event(
        ts=parse_ts(row.get("TimeCreated")),
        tenant=tenant,
        source="ad",
        vendor="Microsoft",
        product="Active Directory",
        event_type=event_type,
        event_subtype=str(event_id) if event_id is not None else None,
        severity=severity,
        action=action,
        src_ip=clean_ip(row.get("IpAddress")),
        src_port=to_port(row.get("IpPort")),
        user=blank_to_none(row.get("TargetUserName")),
        host=blank_to_none(row.get("Computer")),
        raw=dict(original),
        tags=list(tags),  # copy: the table's lists must not be shared between events
    )
