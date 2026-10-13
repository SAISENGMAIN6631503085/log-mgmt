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
        # event_type=/event= (Juniper-style "event=link-down"), else the program tag
        # (Cisco "%LINK-3-UPDOWN"), else "system".
        event_type=kv.get("event_type") or kv.get("event") or (msg.tag.lstrip("%") if msg.tag else "system"),
        event_subtype=kv.get("interface") or kv.get("if") or kv.get("reason"),
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
