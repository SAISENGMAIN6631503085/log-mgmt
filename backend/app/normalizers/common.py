"""The common event schema and small helpers shared by every normalizer.

Normalizers are pure functions: (payload, tenant) -> Event. No DB, no clock unless passed in,
so each one can be unit-tested with a literal sample.
"""
import ipaddress
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Source = Literal["firewall", "network", "api", "crowdstrike", "aws", "m365", "ad"]
Action = Literal["allow", "deny", "create", "delete", "login", "logout", "alert", "quarantine"]

AUTH_FAILURE = "auth_failure"  # tag the brute-force alert rule looks for


class Event(BaseModel):
    """One normalized event. Field names match the common schema in CLAUDE.md.

    Validation here is the last line of defence: a normalizer bug that produces e.g.
    severity=42 fails loudly in tests instead of being stored.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    ts: datetime  # "@timestamp" in the API
    tenant: str
    source: Source
    vendor: str | None = None
    product: str | None = None
    event_type: str | None = None
    event_subtype: str | None = None
    severity: int | None = Field(default=None, ge=0, le=10)
    action: Action | None = None
    src_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    user: str | None = None
    host: str | None = None
    process: str | None = None
    url: str | None = None
    http_method: str | None = None
    status_code: int | None = None
    rule_name: str | None = None
    rule_id: str | None = None
    cloud_account_id: str | None = None
    cloud_region: str | None = None
    cloud_service: str | None = None
    raw: dict[str, Any]
    # Pydantic treats leading-underscore names as private, so the field is `tags` with alias `_tags`.
    tags: list[str] = Field(default_factory=list, alias="_tags")

    @field_validator("ts")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        # Naive datetimes are ambiguous; every source we parse is UTC unless it says otherwise.
        return v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v.astimezone(timezone.utc)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        if v is not None:
            ipaddress.ip_address(v)  # raises -> ValidationError; normalizers should use clean_ip()
        return v


# Field aliases seen across vendors, mapped to the common schema names.
ALIASES = {
    "ip": "src_ip", "src": "src_ip", "srcip": "src_ip", "source_ip": "src_ip", "client_ip": "src_ip",
    "dst": "dst_ip", "dstip": "dst_ip", "destination_ip": "dst_ip",
    "spt": "src_port", "sport": "src_port", "srcport": "src_port",
    "dpt": "dst_port", "dport": "dst_port", "dstport": "dst_port",
    "proto": "protocol",
}


def unify_aliases(d: dict[str, Any]) -> dict[str, Any]:
    """Rename alias keys to schema names. An explicit schema key wins over an alias."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        target = ALIASES.get(k.lower(), k)
        if target not in out or k == target:
            out[target] = v
    return out


_EMPTY = {None, "", "-", "n/a", "N/A"}


def blank_to_none(v: Any) -> Any:
    """Logs use many spellings of "no value" ('-' in Windows CSVs, '' in JSON)."""
    return None if (isinstance(v, str) and v.strip() in _EMPTY) or v is None else v


def to_int(v: Any) -> int | None:
    v = blank_to_none(v)
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def to_port(v: Any) -> int | None:
    """Port 0 means 'not applicable' in Windows logs, so treat it as missing."""
    p = to_int(v)
    return p if p is not None and 0 < p <= 65535 else None


def clean_ip(v: Any) -> str | None:
    """Return a valid IP string or None. Logs put hostnames, 'ip:port' and '-' in IP fields;
    one junk field shouldn't make us drop the whole event."""
    v = blank_to_none(v)
    if not isinstance(v, str):
        return None
    v = v.strip().strip("[]")
    for candidate in (v, v.rsplit(":", 1)[0].strip("[]")):  # second try strips ':port'
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def parse_ts(v: Any) -> datetime:
    """Parse ISO-8601 strings (with or without zone) and epoch seconds/milliseconds into UTC."""
    if isinstance(v, datetime):
        dt = v
    elif isinstance(v, (int, float)):
        # Epoch in ms is > 1e11 for any date after 1973; seconds won't reach that until year 5138.
        dt = datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc)
    elif isinstance(v, str) and v.strip():
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    else:
        raise ValueError(f"missing or unparseable timestamp: {v!r}")
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
