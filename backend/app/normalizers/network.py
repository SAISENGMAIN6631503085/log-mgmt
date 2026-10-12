"""Network device syslog (switches, routers) -> Event."""
from datetime import datetime

from .common import Event, clean_ip, to_port, unify_aliases
from .syslog import parse_syslog


def normalize(line: str, tenant: str, *, now: datetime | None = None) -> Event:
    msg = parse_syslog(line, now=now)
    kv = unify_aliases(msg.kv)
    return Event(
        ts=msg.ts,
        tenant=tenant,
        source="network",
        vendor=kv.get("vendor"),
        product=kv.get("product"),
        # Fall back to the program tag (e.g. Cisco "%LINK-3-UPDOWN") when there is no event_type.
        event_type=kv.get("event_type") or (msg.tag.lstrip("%") if msg.tag else "system"),
        event_subtype=kv.get("interface"),
        severity=msg.severity,
        src_ip=clean_ip(kv.get("src_ip")),
        src_port=to_port(kv.get("src_port")),
        dst_ip=clean_ip(kv.get("dst_ip")),
        dst_port=to_port(kv.get("dst_port")),
        protocol=(kv.get("protocol") or "").lower() or None,
        user=kv.get("user"),
        host=msg.host,
        process=msg.tag,
        raw={"message": line},
    )
