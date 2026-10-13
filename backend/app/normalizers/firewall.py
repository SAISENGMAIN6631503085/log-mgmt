"""Firewall syslog (FortiGate, PAN-OS, ... in key=value form) -> Event."""
from datetime import datetime

from .common import Event, clean_ip, to_port, unify_aliases
from .syslog import parse_syslog

# Every vendor has its own verb for allow/deny; the schema only has two.
_ACTIONS = {
    "accept": "allow", "allow": "allow", "permit": "allow", "pass": "allow",
    "deny": "deny", "drop": "deny", "block": "deny", "reject": "deny",
}


def normalize(line: str, tenant: str, *, now: datetime | None = None) -> Event:
    msg = parse_syslog(line, now=now)
    kv = unify_aliases(msg.kv)
    action = _ACTIONS.get(kv.get("action", "").lower())
    return Event(
        ts=msg.ts,
        tenant=tenant,
        source="firewall",
        vendor=kv.get("vendor"),
        product=kv.get("product"),
        event_type=kv.get("event_type", "traffic"),
        event_subtype=kv.get("event_subtype"),
        severity=msg.severity,
        action=action,
        src_ip=clean_ip(kv.get("src_ip")),
        src_port=to_port(kv.get("src_port")),
        dst_ip=clean_ip(kv.get("dst_ip")),
        dst_port=to_port(kv.get("dst_port")),
        protocol=(kv.get("protocol") or "").lower() or None,
        user=kv.get("user"),
        host=msg.host,
        rule_name=kv.get("rule_name") or kv.get("policy"),  # e.g. policy=Block-DNS
        rule_id=kv.get("rule_id"),
        raw={"message": line},
        tags=["blocked"] if action == "deny" else [],
    )
