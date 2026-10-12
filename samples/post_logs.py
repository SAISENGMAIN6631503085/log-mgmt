#!/usr/bin/env python3
"""Send the JSON/CSV sample files to the HTTP ingest API. Python standard library only.

Timestamps in each file are shifted so the newest event is "now" (keeping the gaps between
events, so the brute-force burst in ad_security.csv still fits in 5 minutes). Without this
the samples would fall outside the 7-day retention window and be rejected.

    python3 samples/post_logs.py                         # every sample, tenant demoA, JSON API
    python3 samples/post_logs.py --mode file             # same, through the file-upload endpoint
    python3 samples/post_logs.py --key lm_demoB_... aws  # one source, another tenant
    python3 samples/post_logs.py --no-shift               # keep original timestamps
"""
import argparse
import csv
import io
import json
import ssl
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
SAMPLES = {  # source -> (file, timestamp field)
    "api": ("api_events.json", "timestamp"),
    "aws": ("aws_cloudtrail.json", "eventTime"),
    "m365": ("m365_audit.json", "CreationTime"),
    "crowdstrike": ("crowdstrike_detections.ndjson", "metadata.eventCreationTime"),
    "ad": ("ad_security.csv", "TimeCreated"),
}


def load(source: str) -> list[dict]:
    name = SAMPLES[source][0]
    text = (HERE / name).read_text()
    if name.endswith(".csv"):
        return list(csv.DictReader(io.StringIO(text)))
    if name.endswith(".ndjson"):
        return [json.loads(l) for l in text.splitlines() if l.strip()]
    data = json.loads(text)
    return data["Records"] if isinstance(data, dict) and "Records" in data else data


# --- timestamp shifting (handles ISO strings, zone-less ISO, and epoch milliseconds) ---

def _get(rec, path):
    for part in path.split("."):
        rec = rec[part]
    return rec


def _set(rec, path, value):
    *parents, last = path.split(".")
    for part in parents:
        rec = rec[part]
    rec[last] = value


def _parse(v) -> datetime:
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v / 1000, tz=timezone.utc)
    dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _format(dt: datetime, like) -> object:
    if isinstance(like, (int, float)):
        return int(dt.timestamp() * 1000)
    if str(like).endswith("Z"):
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if "+" not in str(like)[10:]:
        return dt.strftime("%Y-%m-%dT%H:%M:%S")  # M365 style: no zone, UTC implied
    return dt.isoformat()


def shift_to_now(records: list[dict], field: str) -> list[dict]:
    times = [_parse(_get(r, field)) for r in records]
    offset = datetime.now(timezone.utc) - timedelta(seconds=5) - max(times)
    for r, t in zip(records, times):
        _set(r, field, _format(t + offset, _get(r, field)))
    return records


# --- HTTP ---

def post(url: str, key: str, body: bytes, content_type: str, insecure: bool) -> dict:
    # Appliance mode uses Caddy's self-signed certificate, so verification is off by default for localhost.
    ctx = ssl._create_unverified_context() if insecure else None
    req = Request(url, data=body, method="POST", headers={"X-API-Key": key, "Content-Type": content_type})
    try:
        with urlopen(req, context=ctx, timeout=30) as r:
            return json.loads(r.read())
    except HTTPError as e:
        return {"error": e.code, "detail": e.read().decode(errors="replace")}


def to_file(source: str, records: list[dict]) -> tuple[str, bytes]:
    """Re-serialize shifted records in the sample's original format, for the upload endpoint."""
    name = SAMPLES[source][0]
    if name.endswith(".csv"):
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(records[0]))
        w.writeheader()
        w.writerows(records)
        return name, buf.getvalue().encode()
    if name.endswith(".ndjson"):
        return name, "".join(json.dumps(r) + "\n" for r in records).encode()
    if source == "aws":
        return name, json.dumps({"Records": records}).encode()
    return name, json.dumps(records).encode()


def multipart(fields: dict[str, str], filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in fields.items()]
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                 f"Content-Type: application/octet-stream\r\n\r\n".encode() + content + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="*", default=list(SAMPLES), help=f"default: all of {list(SAMPLES)}")
    ap.add_argument("--url", default="https://localhost")
    ap.add_argument("--key", default="lm_demoA_dev_key_change_me", help="tenant API key (X-API-Key)")
    ap.add_argument("--mode", choices=["json", "file"], default="json", help="JSON API or file upload")
    ap.add_argument("--no-shift", action="store_true", help="keep the original timestamps")
    ap.add_argument("--verify-tls", action="store_true", help="verify the certificate (use for real domains)")
    args = ap.parse_args()

    insecure = not args.verify_tls
    ok = True
    for source in args.sources:
        if source not in SAMPLES:
            print(f"unknown source {source!r}", file=sys.stderr)
            return 2
        records = load(source)
        if not args.no_shift:
            shift_to_now(records, SAMPLES[source][1])
        if args.mode == "json":
            result = post(f"{args.url}/api/ingest?source={source}", args.key,
                          json.dumps(records).encode(), "application/json", insecure)
        else:
            body, ctype = multipart({"source": source}, *to_file(source, records))
            result = post(f"{args.url}/api/ingest/file", args.key, body, ctype, insecure)
        ok &= "error" not in result
        print(f"{source:12} {result}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
