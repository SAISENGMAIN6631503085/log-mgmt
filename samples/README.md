# Samples

Realistic example logs for each source. They are modeled on each product's real format,
but the data is synthetic and uses documentation IP ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24). The normalizer tests read these files, so they double as test fixtures.

| File | Source | Format |
|------|--------|--------|
| `firewall.log` | firewall | RFC 3164 syslog, key=value (FortiGate / PAN-OS style) |
| `network.log` | network | Cisco IOS-style syslog |
| `api_events.json` | api | JSON array |
| `crowdstrike_detections.ndjson` | crowdstrike | NDJSON, Falcon streaming API |
| `aws_cloudtrail.json` | aws | CloudTrail file (`{"Records": [...]}`) |
| `m365_audit.json` | m365 | Management Activity API JSON array |
| `ad_security.csv` | ad | Windows Security events as CSV |

`ad_security.csv` includes six failed logons (4625) from 203.0.113.50 within two minutes,
which is enough to trigger the brute-force alert rule.

## Demo scripts
All scripts **move timestamps to "now"**, so the samples land inside the 7-day retention
window on any day. The sample files themselves are dated 2026-10-12.

| Script | What it does |
|--------|--------------|
| `send_syslog.sh` | Sends `firewall.log` and `network.log` to Vector (UDP 514; `-t` for TCP, `-h host`). Uses bash's `/dev/udp`, so no netcat is needed. |
| `post_logs.py` | Sends the JSON/CSV samples to the API (`--mode json`) or as file uploads (`--mode file`). `--key` picks the tenant. Python standard library only. |
| `simulator.py` | Continuous realistic traffic for every tenant key, plus a staged attack every `--attack-every` seconds, taking turns so every alert rule fires live: a brute force (6 failed AD logons from one IP), a port scan (25 blocked firewall connections from one IP, over syslog) and malware (a high-severity CrowdStrike detection). |

`make demo` runs the first two for both demo tenants; `make simulate` runs the simulator.

The sample files use documentation addresses (`203.0.113.x`, `198.51.100.x`, `192.0.2.x`), which
have no country. The simulator uses blocks of real public addresses instead (large ISP and cloud
networks, each checked against the DB-IP database), so the dashboard shows realistic countries. It
only writes them into generated log text and never contacts them.
To keep it running in the background (as the live demo does), set `COMPOSE_PROFILES=demo` in `.env`
and `make up`: the `simulator` service sends a gentler stream (`--rate 0.3 --daily-cycle`, busier by
day than at night) with an attack every 15 minutes. `simulator.py --keys` also accepts the
`SEED_API_KEYS` format (`demoA=key,demoB=key`).
Running `post_logs.py` again creates new events (new timestamps), which is not counted as duplicates.
Sending a file with the same timestamps twice is skipped as duplicates.
