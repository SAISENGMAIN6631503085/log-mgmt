# Ingest (Go service + Vector)

Everything that brings logs **in**: the Go ingest service, which receives every log, normalizes
it into the common schema and stores it in ClickHouse, and Vector, which receives syslog.

```
devices ──syslog 514──▶ Vector ──HTTP + X-Ingest-Token──▶ ┐
apps / scripts ──HTTPS + X-API-Key──▶ Caddy ─────────────▶ ├─▶ ingest (Go) ──▶ ClickHouse
website "Add logs" ──HTTPS + login token──▶ Caddy ───────▶ ┘        │
                                                 Postgres ◀─────────┘ (API keys)
```

**Why Go here, and Python for the rest:** ingestion is the one part that handles every single
log, so it's the part that must keep up as volume grows. Go handles many requests per CPU core,
uses little memory and ships as one small binary (the image is ~30 MB). Login, search, the
dashboard and alerts stay in the Python backend: there, requests are few and the code is mostly
business rules. This is a common split in real log platforms: a fast language on the busy path,
whatever the team builds fastest in for the rest.

## Layout
| Path | What |
|------|------|
| `main.go` | settings from env vars, wiring, graceful shutdown, `-healthcheck` for Docker |
| `server/` | the HTTP endpoints, API key and login-token checks, file parsing |
| `normalize/` | one pure function per source (`firewall.go`, `aws.go`, …) plus syslog parsing |
| `store/` | writes to ClickHouse: duplicate check, ids, fingerprints |
| `geoip/` | country of the source IP (DB-IP Lite, downloaded when the image is built) |
| `vector.yaml` | Vector: syslog on 514 → `http://ingest:8080/api/ingest/syslog` |
| `Dockerfile` | build stage (Go + GeoIP download) → distroless runtime (no shell, non-root, amd64 + arm64) |

## Endpoints
All of them normalize events, store the valid ones, and report the rest:
`{"accepted": n, "time_adjusted": t, "duplicates": d, "rejected_count": m, "rejected": [{"index": i, "error": "..."}]}`.
One bad event never blocks the rest of the batch.

| Endpoint | Auth | Body |
|----------|------|------|
| `POST /api/ingest` (alias `POST /ingest`) | `X-API-Key` | one JSON event or an array. The normalizer comes from `?source=`, else each event's own `"source"` field, else `api`. A `{"Records": [...]}` body is CloudTrail. |
| `POST /api/ingest/file` | `X-API-Key` | multipart: `source` + `file` (.json, .ndjson/.jsonl, .csv, .log/.txt), max 50 MB |
| `POST /api/ingest/upload` | login token, **admin** | the same upload for the website's **Add logs** page. The tenant is the one being viewed (`?tenant=`); viewers get 403 because they're read-only. |
| `POST /api/ingest/syslog` | `X-Ingest-Token` | internal, Vector only; blocked by Caddy from outside |
| `GET /health` | none | `{"status": "ok"}` (Docker's health check; not routed by Caddy) |

Rules:
- **The tenant always comes from the API key** (looked up by its SHA-256 in Postgres' `api_keys`,
  which the backend manages) or, for syslog, from the sender IP. An event whose own `tenant` field
  names a *different* tenant is **rejected** with a clear message, so a wrong key or a cross-tenant
  write attempt is visible.
- The upload's login token is checked with the same `JWT_SECRET` the backend signs it with: HS256
  only (the token can't pick its own algorithm), `exp` required, role must be admin.
- At most 10,000 events per request; above that the request gets 413.
- Events older than `RETENTION_DAYS` or more than 1 day in the future are **stored at the receipt
  time, tagged `time_adjusted`**, and keep their original timestamp in `raw`. Storing them at their
  real (old) time would get them deleted by retention, and rejecting them would drop real activity
  from devices with a wrong clock or from old sample files.
- If ClickHouse is down, the answer is 503 and nothing is stored, so the sender retries (Vector
  does so by itself). Duplicates are skipped, so a retry is always safe.

```
curl -k https://localhost/api/ingest -H "X-API-Key: lm_demoA_dev_key_change_me" \
     -H "content-type: application/json" -d '{"event_type":"login_failed","user":"alice","ip":"203.0.113.7"}'
curl -k https://localhost/api/ingest/file -H "X-API-Key: lm_demoA_dev_key_change_me" \
     -F source=aws -F file=@samples/aws_cloudtrail.json
```

## Normalizers (`normalize/`)
Each source has one pure function, `(payload, tenant, now) → *Event`, with no database or network
access, so each is unit-tested against `/samples`. `Event.Validate()` rejects impossible values
(severity 42, a bad IP, an unknown source) so a mapping bug fails loudly instead of being stored.

| Source | Input | Notes |
|--------|-------|-------|
| `firewall` | syslog line, key=value | accept/permit/pass → `allow`; deny/drop/block/reject → `deny` + tag `blocked` |
| `network` | syslog line | `event_type` falls back to the program tag (e.g. `%LINK-3-UPDOWN`) |
| `api` | JSON object | auth-related `*_failed` → `login` + `auth_failure` |
| `crowdstrike` | Falcon DetectionSummaryEvent or the flat sample | severity 1–5 ×2; quarantined → `quarantine`, else `alert` |
| `aws` | CloudTrail record (`IterRecords` unwraps `{"Records": [...]}`) | failed ConsoleLogin → `auth_failure`; Root → `root_activity` |
| `m365` | Management Activity audit record | failed status → `login` + `auth_failure`; forwarding inbox rule flagged |
| `ad` | Windows Security event (CSV row or JSON) | 4625 → `login` + `auth_failure`; 4624/4634/4720/4726/4740 mapped |

Each accepts the vendor's real format **and** the flat format of the assignment's samples
(`@timestamp`, `event_type`, `user`, `ip`, `cloud: {...}`).

Shared rules (`common.go`):
- `UnifyAliases` renames `ip`/`src` → `src_ip`, `dst` → `dst_ip`, `spt`/`dpt` → ports, `proto` → `protocol`.
- `CleanIP` turns hostnames, `-` and `ip:port` into a clean IP or nothing.
- `ParseTS` reads ISO-8601 (no zone = UTC) and epoch seconds or milliseconds.
- JSON is decoded with numbers kept exactly as written, so ids in the original log aren't rounded.

Syslog (`syslog.go`):
- `<PRI> % 8` maps to severity 10/9/8/7/5/3/2/0.
- Timestamps without a year use the current year in UTC; a line more than a day "in the future"
  is moved to the previous year (a Dec 31 line arriving on Jan 1).
- The tenant comes from the sender IP via `SYSLOG_TENANT_MAP` (most specific network wins), else
  `DEFAULT_TENANT`. Firewall vs network is decided from the content: an allow/deny `action` plus
  addresses means firewall.

## Storing (`store/`)
- **Duplicates:** an event already stored is counted in `duplicates` and not stored again, so
  re-uploading a file or Vector retrying a batch is safe. The fingerprint is
  `sha256(JSON [tenant, source, raw] with sorted keys)`, the same however the JSON was formatted,
  and always computed here, so a caller can't forge one. A duplicate is the same fingerprint **at
  the same time**. ClickHouse has no unique constraint, so existing pairs are looked up first (in
  chunks of 300, since the values travel in the URL); `ReplacingMergeTree` on the same key removes
  anything that slips through when it merges.
- Events stored at their receipt time because their own time was out of range (`time_adjusted`)
  get a new stored time on every send, so for them the fingerprint **alone** decides. Their real
  time is inside the original log, which the fingerprint covers, so re-uploading an old file still
  counts as duplicates.
- The fingerprint text is byte-for-byte what the earlier Python version hashed (non-ASCII as
  `\uXXXX`), so events stored before the move still count as duplicates.
- **Ids** are time-ordered and below 2^53, so browsers (JSON numbers are doubles) show them exactly.
- Values are typed query parameters (`{tenants:Array(String)}`), never pasted into SQL.

## Country enrichment (`geoip/`)
After normalizing, the country of `src_ip` is stored as `src_country` (two-letter code). It's then
a search filter, a dashboard table and part of each IP-based alert.
- Data: DB-IP "IP to Country Lite", free under CC BY 4.0 (the website links to db-ip.com, as the
  licence asks). The Dockerfile downloads this month's file (or last month's); lookups read the
  local file, so no log data leaves the server. Refresh with `docker compose build --no-cache ingest`.
- Private and reserved addresses (10.x, 192.168.x, the documentation ranges in the samples) have
  no country. Without the file, enrichment is off and nothing else changes.

## Syslog with Vector
`vector.yaml` listens on UDP and TCP 514 and POSTs batches to `/api/ingest/syslog`.
- It uses Vector's plain `socket` source, not the `syslog` one, so the service gets the untouched
  line plus the sender IP: `{"message": "<134>Oct 12 ...", "host": "10.0.1.5"}`. All parsing happens
  in the unit-tested Go code.
- Each request carries `X-Ingest-Token: $SYSLOG_INGEST_TOKEN` (compared in constant time; an empty
  configured token refuses everything). Caddy also returns 404 for `/api/ingest/syslog` from
  outside, so only Vector, on the Docker network, can reach it.
- If the service is down, Vector retries, so messages are not lost during short outages.

Try it: `./samples/send_syslog.sh`, or by hand:
```
echo "<132>$(date -u '+%b %e %H:%M:%S') fw01 action=deny src=203.0.113.45 dst=10.0.0.10 dpt=22" | nc -u -w1 127.0.0.1 514
```
Port 514 is published on IPv4 at `SYSLOG_BIND` (default `0.0.0.0`; use `127.0.0.1` to keep it off
a public network). Use `127.0.0.1` rather than `localhost`, which may resolve to IPv6 first.

Note: with Docker Desktop (Mac/Windows), the sender IP that Vector sees is Docker's gateway, not
the real device, so every message gets `DEFAULT_TENANT`. On a Linux VM the real sender IP is kept.

## Tests
`make test` runs `go test ./...` in a Go container on the compose network (service `ingest-test`),
after the pytest suite. Unit tests cover every normalizer (against `/samples` and the assignment's
own samples), file parsing, the endpoints (with in-memory stand-ins for the databases) and ids;
the `store` tests also write to the real ClickHouse. The pytest suite sends logs to the running
service end to end (`tests/test_ingest_api.py`, `test_dedup.py`, `test_assignment_samples.py`).

Settings (all from `.env`, see `/.env.example`): `POSTGRES_*`, `CLICKHOUSE_URL`/`_DB`/`_USER`/`_PASSWORD`,
`JWT_SECRET`, `SYSLOG_INGEST_TOKEN`, `SYSLOG_TENANT_MAP`, `DEFAULT_TENANT`, `RETENTION_DAYS`, `GEOIP_DB`.
