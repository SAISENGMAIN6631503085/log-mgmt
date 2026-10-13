"""IP -> country enrichment, done once at ingest so search, stats and alerts can use it.

Data: DB-IP "IP to Country Lite" (free, CC BY 4.0: the website links to db-ip.com as the
licence asks). The file is downloaded when the backend image is built (fetch_geoip.py) and
read locally: no lookup ever leaves the server.

If the file is missing (e.g. the build had no internet), enrichment is simply off: events
are stored without a country, and nothing else changes.
"""
import functools
import logging
import os

import maxminddb

from .config import settings

log = logging.getLogger("geoip")


@functools.cache
def _reader():
    path = settings.geoip_db
    if not path or not os.path.exists(path):
        log.warning("GeoIP database not found at %r; country enrichment is off", path)
        return None
    return maxminddb.open_database(path)


def enabled() -> bool:
    return _reader() is not None


# Same IPs repeat a lot in logs (attackers, offices), so cache recent answers.
@functools.lru_cache(maxsize=50_000)
def country(ip: str | None) -> str | None:
    """Two-letter country code ("TH", "DE"), or None for private, reserved or unknown IPs
    (10.x, 192.168.x and the documentation ranges used in the assignment samples have no country)."""
    if not ip:
        return None
    reader = _reader()
    if reader is None:
        return None
    try:
        record = reader.get(ip)
    except ValueError:
        return None
    return ((record or {}).get("country") or {}).get("iso_code")
