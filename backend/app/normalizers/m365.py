"""Microsoft 365 Management Activity API audit records -> Event."""
from typing import Any

from .common import AUTH_FAILURE, Event, clean_ip, parse_ts

_FAILED = {"failed", "failure"}
_LOGIN_OPS = {"UserLoggedIn", "UserLoginFailed"}


def normalize(record: dict[str, Any], tenant: str, **_) -> Event:
    op = record.get("Operation", "")
    failed = str(record.get("ResultStatus", "")).lower() in _FAILED or op == "UserLoginFailed"
    tags: list[str] = []
    severity = 2
    action = None

    if op in _LOGIN_OPS or (failed and record.get("Workload") == "AzureActiveDirectory"):
        action = "login"
        if failed:
            tags.append(AUTH_FAILURE)
            severity = 5
    elif op.startswith(("New-", "Add", "Set-")) or op.endswith(("Created", "Uploaded", "Added")):
        action = "create"
    elif op.startswith(("Remove-", "Delete")) or op.endswith(("Deleted", "Removed")):
        action, severity = "delete", 4

    # Mail forwarding to an outside address is a common account-takeover step.
    params = {p.get("Name"): p.get("Value") for p in record.get("Parameters") or [] if isinstance(p, dict)}
    if op in ("New-InboxRule", "Set-InboxRule") and any(k in params for k in ("ForwardTo", "RedirectTo")):
        tags.append("mail_forwarding_rule")
        severity = max(severity, 6)

    return Event(
        ts=parse_ts(record.get("CreationTime")),  # no zone in the API; documented as UTC
        tenant=tenant,
        source="m365",
        vendor="Microsoft",
        product="Microsoft 365",
        event_type=op or None,
        event_subtype=record.get("LogonError"),
        severity=severity,
        action=action,
        src_ip=clean_ip(record.get("ClientIP")),  # Exchange sends "ip:port"; clean_ip strips it
        user=record.get("UserId"),
        url=record.get("ObjectId") if str(record.get("ObjectId", "")).startswith("http") else None,
        cloud_account_id=record.get("OrganizationId"),
        cloud_service=record.get("Workload"),
        raw=record,
        tags=tags,
    )
