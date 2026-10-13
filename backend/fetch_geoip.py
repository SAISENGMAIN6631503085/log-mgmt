"""Build step: download DB-IP's free IP-to-country database (CC BY 4.0) into the image.

DB-IP publishes a new file each month (dbip-country-lite-YYYY-MM.mmdb.gz); early in a month the
new one may not be out yet, so fall back to last month's. Never fails the build: without the
file the backend just stores events without a country (see app/geoip.py).

Usage: python fetch_geoip.py /app/geoip/dbip-country-lite.mmdb
"""
import gzip
import sys
import urllib.request
from datetime import date, timedelta
from pathlib import Path

URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz"


def main(target: str) -> None:
    out = Path(target)
    out.parent.mkdir(parents=True, exist_ok=True)
    this_month = date.today().replace(day=1)
    for month in (this_month, (this_month - timedelta(days=1)).replace(day=1)):
        url = URL.format(month=month.strftime("%Y-%m"))
        try:
            # DB-IP refuses Python's default User-Agent ("Python-urllib") with 403.
            req = urllib.request.Request(url, headers={"User-Agent": "log-mgmt-build/1.0 (+https://db-ip.com)"})
            with urllib.request.urlopen(req, timeout=60) as r:
                out.write_bytes(gzip.decompress(r.read()))
            print(f"geoip: downloaded {url} ({out.stat().st_size // 1024} KB)")
            return
        except Exception as exc:  # noqa: BLE001 - any failure: try the next month, then give up quietly
            print(f"geoip: {url} failed: {exc}")
    print("geoip: no database downloaded; country enrichment will be off")


if __name__ == "__main__":
    main(sys.argv[1])
