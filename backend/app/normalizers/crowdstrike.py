"""CrowdStrike -> Event. Accepts Falcon streaming API events (DetectionSummaryEvent) and the
flat format used in the assignment ({"event_type": "malware_detected", "host": ..., "severity": 8})."""
from typing import Any

from .common import Event, clean_ip, flat_time, parse_ts, to_int, unify_aliases

_ACTIONS = {"allow", "deny", "create", "delete", "login", "logout", "alert", "quarantine"}


def _normalize_flat(payload: dict[str, Any], tenant: str) -> Event:
    d = unify_aliases(payload)
    severity = to_int(d.get("severity"))
    action = str(d.get("action") or "").lower()
    action = action if action in _ACTIONS else "alert"
    return Event(
        ts=parse_ts(flat_time(d)),
        tenant=tenant,
        source="crowdstrike",
        vendor=d.get("vendor") or "CrowdStrike",
        product=d.get("product") or "Falcon",
        event_type=d.get("event_type"),
        event_subtype=d.get("event_subtype"),
        severity=severity if severity is not None and 0 <= severity <= 10 else None,
        action=action,
        src_ip=clean_ip(d.get("src_ip")),
        user=d.get("user"),
        host=d.get("host"),
        process=d.get("process"),
        rule_name=d.get("rule_name"),
        rule_id=d.get("rule_id"),
        raw=payload,
        tags=["edr_detection"] + (["quarantined"] if action == "quarantine" else []),
    )


def normalize(payload: dict[str, Any], tenant: str, **_) -> Event:
    if "metadata" not in payload and "event" not in payload:
        return _normalize_flat(payload, tenant)
    meta = payload.get("metadata", {})
    ev = payload.get("event", {})
    flags = ev.get("PatternDispositionFlags") or {}
    description = (ev.get("PatternDispositionDescription") or "").lower()

    # Falcon severity is 1 (info) .. 5 (critical); double it onto our 0-10 scale.
    cs_sev = to_int(ev.get("Severity"))
    severity = min(cs_sev * 2, 10) if cs_sev is not None else None

    quarantined = flags.get("QuarantineFile") or "quarantine" in description
    event_type = meta.get("eventType", "")
    return Event(
        ts=parse_ts(meta.get("eventCreationTime")),  # epoch milliseconds
        tenant=tenant,
        source="crowdstrike",
        vendor="CrowdStrike",
        product="Falcon",
        event_type="detection" if event_type == "DetectionSummaryEvent" else event_type or None,
        event_subtype=ev.get("Tactic"),
        severity=severity,
        action="quarantine" if quarantined else "alert",
        src_ip=clean_ip(ev.get("LocalIP")),
        user=ev.get("UserName"),
        host=ev.get("ComputerName"),
        process=ev.get("FileName"),
        rule_name=ev.get("DetectName") or ev.get("Technique"),
        rule_id=ev.get("DetectId"),
        raw=payload,
        tags=["edr_detection"] + (["quarantined"] if quarantined else []),
    )
