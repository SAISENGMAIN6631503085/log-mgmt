"""CrowdStrike Falcon streaming API events (DetectionSummaryEvent) -> Event."""
from typing import Any

from .common import Event, clean_ip, parse_ts, to_int


def normalize(payload: dict[str, Any], tenant: str, **_) -> Event:
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
