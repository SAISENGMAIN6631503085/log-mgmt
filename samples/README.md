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
