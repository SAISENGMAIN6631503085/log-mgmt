"""Pure helpers for turning request bodies / uploaded files into lists of raw payloads."""
import csv
import io
import json
from typing import Any

from .normalizers import aws
from .normalizers.syslog import parse_syslog

SYSLOG_SOURCES = {"firewall", "network"}


def split_payloads(source: str, body: Any) -> list[Any]:
    """A JSON body may be one event, an array, or (AWS) a CloudTrail {"Records": [...]} file."""
    if source == "aws":
        return list(aws.iter_records(body))
    if isinstance(body, list):
        return body
    if isinstance(body, (dict, str)):
        return [body]
    raise ValueError("body must be a JSON object or array")


def parse_upload(filename: str, content: bytes, source: str) -> list[Any]:
    """Detect the file format from its extension (falling back to sniffing the content).

    .csv -> one dict per row; .ndjson/.jsonl -> one object per line; .json -> object/array;
    .log/.txt (or any text for syslog sources) -> one syslog line per line.
    """
    text = content.decode("utf-8-sig")  # -sig strips the BOM that Excel/PowerShell exports add
    name = filename.lower()
    lines = [l for l in text.splitlines() if l.strip()]

    if name.endswith(".csv"):
        return list(csv.DictReader(io.StringIO(text)))
    if name.endswith((".ndjson", ".jsonl")):
        return [json.loads(l) for l in lines]
    if name.endswith((".log", ".txt")) or source in SYSLOG_SOURCES:
        return lines
    if name.endswith(".json") or text.lstrip()[:1] in ("[", "{"):
        try:
            return split_payloads(source, json.loads(text))
        except json.JSONDecodeError:
            return [json.loads(l) for l in lines]  # NDJSON saved with a .json name
    raise ValueError(f"unsupported file type: {filename!r} (use .json, .ndjson, .csv or .log)")


def classify_syslog(line: str) -> str:
    """Syslog has no 'source' field, so decide firewall vs network from content.

    Firewalls log traffic decisions: an action plus addresses. Everything else from a
    syslog device (link up/down, config changes, routing) is treated as network.
    """
    try:
        kv = parse_syslog(line).kv
    except ValueError:
        return "network"  # unparseable; the network normalizer will report the real error
    has_action = kv.get("action", "").lower() in {
        "accept", "allow", "permit", "pass", "deny", "drop", "block", "reject"}
    has_addr = any(k in kv for k in ("src", "dst", "ip", "srcip", "dstip", "src_ip", "dst_ip"))
    return "firewall" if has_action and has_addr else "network"
