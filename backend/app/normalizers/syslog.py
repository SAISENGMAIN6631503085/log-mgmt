"""Syslog line parsing shared by the firewall and network normalizers.

Supported: RFC 3164 (`<PRI>Mmm dd hh:mm:ss host msg`) and the common variant with an
RFC 3339 timestamp (`<PRI>[1 ]2026-10-12T08:15:01Z host msg`). The message body is then
scanned for key=value pairs, which is how most firewalls emit fields.
"""
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .common import parse_ts

_HEADER = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?:1 )?"  # RFC 5424 version digit, if present
    r"(?P<ts>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)"
    r" (?P<host>\S+) ?(?P<msg>.*)$",
    re.DOTALL,
)
# Program tag before the message: "sshd[123]: ..." or Cisco "%LINK-3-UPDOWN: ..."
_TAG = re.compile(r"^(?P<tag>%?[\w./-]+)(?:\[\d+\])?: ")
# key=value or key="value with spaces"
_KV = re.compile(r'(?P<k>[A-Za-z_][\w.-]*)=(?:"(?P<q>[^"]*)"|(?P<v>[^\s"]*))')

# Syslog severity 0 (emergency) .. 7 (debug) -> our 0..10 scale (10 = worst).
SYSLOG_TO_SEVERITY = {0: 10, 1: 9, 2: 8, 3: 7, 4: 5, 5: 3, 6: 2, 7: 0}


@dataclass
class SyslogMessage:
    ts: datetime
    facility: int
    syslog_severity: int  # raw 0-7
    severity: int         # mapped 0-10
    host: str
    tag: str | None
    message: str
    kv: dict[str, str] = field(default_factory=dict)


def _parse_bsd_timestamp(text: str, now: datetime) -> datetime:
    """RFC 3164 timestamps have no year or zone: assume UTC and the current year.

    Year rollover: a "Dec 31 23:59:59" line received on Jan 1 would land a year in the
    future, so anything more than a day ahead of `now` is moved to the previous year.
    """
    text = " ".join(text.split())  # "Oct  2" (space-padded day) -> "Oct 2"
    dt = datetime.strptime(f"{now.year} {text}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    if dt > now + timedelta(days=1):
        dt = dt.replace(year=now.year - 1)
    return dt


def parse_syslog(line: str, now: datetime | None = None) -> SyslogMessage:
    now = now or datetime.now(timezone.utc)
    m = _HEADER.match(line.strip())
    if not m:
        raise ValueError(f"not a syslog line: {line[:80]!r}")
    pri = int(m["pri"])
    if pri > 191:  # facility max 23 * 8 + severity 7
        raise ValueError(f"invalid syslog PRI {pri}")

    ts_text = m["ts"]
    ts = parse_ts(ts_text) if ts_text[0].isdigit() else _parse_bsd_timestamp(ts_text, now)

    msg = m["msg"]
    tag = None
    if t := _TAG.match(msg):
        tag, msg = t["tag"], msg[t.end():]

    kv = {k.group("k"): (k.group("q") if k.group("q") is not None else k.group("v"))
          for k in _KV.finditer(msg)}
    return SyslogMessage(
        ts=ts,
        facility=pri // 8,
        syslog_severity=pri % 8,
        severity=SYSLOG_TO_SEVERITY[pri % 8],
        host=m["host"],
        tag=tag,
        message=msg,
        kv=kv,
    )


def parse_tenant_map(spec: str) -> list[tuple[ipaddress._BaseNetwork, str]]:
    """Parse SYSLOG_TENANT_MAP, e.g. "10.0.1.0/24=demoA,10.0.2.5=demoB"."""
    out = []
    for item in filter(None, (s.strip() for s in spec.split(","))):
        net, _, tenant = item.partition("=")
        if not tenant:
            raise ValueError(f"SYSLOG_TENANT_MAP entry needs '=tenant': {item!r}")
        out.append((ipaddress.ip_network(net.strip(), strict=False), tenant.strip()))
    return out


def tenant_for_sender(sender_ip: str | None, tenant_map, default: str) -> str:
    """Syslog carries no tenant, so we infer it from which device sent it.
    The most specific matching network wins; unknown senders go to DEFAULT_TENANT."""
    try:
        ip = ipaddress.ip_address(sender_ip) if sender_ip else None
    except ValueError:
        ip = None
    if ip is not None:
        matches = [(net.prefixlen, t) for net, t in tenant_map if ip.version == net.version and ip in net]
        if matches:
            return max(matches)[1]
    return default
