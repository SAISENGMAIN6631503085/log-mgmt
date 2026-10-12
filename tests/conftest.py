import csv
import json
from datetime import datetime, timezone
from pathlib import Path

# Works both in the container (/app/samples is mounted next to /app/tests) and from the repo root.
SAMPLES = Path(__file__).resolve().parent.parent / "samples"

# Fixed "current time" so syslog year inference is deterministic.
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def sample_lines(name: str) -> list[str]:
    return [l for l in (SAMPLES / name).read_text().splitlines() if l.strip()]


def sample_json(name: str):
    return json.loads((SAMPLES / name).read_text())


def sample_ndjson(name: str) -> list[dict]:
    return [json.loads(l) for l in sample_lines(name)]


def sample_csv(name: str) -> list[dict]:
    with open(SAMPLES / name, newline="") as f:
        return list(csv.DictReader(f))
