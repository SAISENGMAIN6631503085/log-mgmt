"""AWS CloudTrail records -> Event."""
from collections.abc import Iterator
from typing import Any

from .common import AUTH_FAILURE, Event, clean_ip, flat_cloud, flat_time, parse_ts

_CREATE_PREFIXES = ("Create", "Run", "Put", "Add", "Attach", "Start")
_DELETE_PREFIXES = ("Delete", "Terminate", "Remove", "Detach")


def iter_records(doc: Any) -> Iterator[dict[str, Any]]:
    """CloudTrail files wrap events as {"Records": [...]}; also accept a bare list or one record."""
    if isinstance(doc, dict) and "Records" in doc:
        yield from doc["Records"]
    elif isinstance(doc, list):
        yield from doc
    else:
        yield doc


def _from_flat(d: dict[str, Any]) -> dict[str, Any]:
    """The assignment's flat AWS sample, reshaped as a CloudTrail record so one mapping serves both."""
    cloud = flat_cloud(d)
    status = str(d.get("status", "")).lower()
    rec: dict[str, Any] = {
        "eventTime": flat_time(d),
        "eventName": d.get("event_type") or (d.get("raw") or {}).get("eventName", ""),
        "eventSource": f"{cloud['service']}.amazonaws.com" if cloud["service"] else None,
        "awsRegion": cloud["region"],
        "recipientAccountId": cloud["account_id"],
        "sourceIPAddress": d.get("src_ip") or d.get("ip"),
        "userIdentity": {"userName": d.get("user")} if d.get("user") else {},
    }
    if rec["eventName"] == "ConsoleLogin" and status:
        rec["responseElements"] = {"ConsoleLogin": "Failure" if status in ("failure", "failed") else "Success"}
    if d.get("error_code"):
        rec["errorCode"] = d["error_code"]
    return rec


def normalize(record: dict[str, Any], tenant: str, **_) -> Event:
    original = record
    if "eventName" not in record and "eventTime" not in record:
        record = _from_flat(record)
    name = record.get("eventName", "")
    identity = record.get("userIdentity") or {}
    tags: list[str] = []
    action = None
    severity = 2

    if name == "ConsoleLogin":
        action = "login"
        if (record.get("responseElements") or {}).get("ConsoleLogin") == "Failure":
            tags.append(AUTH_FAILURE)
            severity = 5
    elif name.startswith(_CREATE_PREFIXES):
        action = "create"
    elif name.startswith(_DELETE_PREFIXES):
        action, severity = "delete", 4

    if record.get("errorCode") in ("AccessDenied", "UnauthorizedOperation") or \
            str(record.get("errorCode", "")).endswith("AccessDenied"):
        action, severity = "deny", max(severity, 5)
        tags.append("access_denied")

    # Root account use is a classic CloudTrail red flag.
    if identity.get("type") == "Root":
        tags.append("root_activity")
        severity = max(severity, 7)

    # IAM users have userName; roles only have an ARN (".../role-name"), and the root ARN
    # ends in ":root" with no slash, so take the last segment after either separator.
    arn = identity.get("arn") or ""
    user = identity.get("userName") or arn.rsplit("/", 1)[-1].rsplit(":", 1)[-1] or None
    if identity.get("type") == "AWSService":
        user = identity.get("invokedBy")

    source_ip = record.get("sourceIPAddress")
    return Event(
        ts=parse_ts(record.get("eventTime")),
        tenant=tenant,
        source="aws",
        vendor="AWS",
        product="CloudTrail",
        event_type=name or None,
        event_subtype=record.get("errorCode"),
        severity=severity,
        action=action,
        # For service-originated calls this is a hostname like "ec2.amazonaws.com", not an IP.
        src_ip=clean_ip(source_ip),
        user=user,
        host=None if clean_ip(source_ip) else source_ip,
        cloud_account_id=record.get("recipientAccountId") or identity.get("accountId"),
        cloud_region=record.get("awsRegion"),
        cloud_service=(record.get("eventSource") or "").split(".")[0] or None,
        raw=original,
        tags=tags,
    )
