# Ingest (Vector)

`vector.yaml` listens for syslog on UDP and TCP port 514 and POSTs batches to the backend's
internal endpoint `http://backend:8000/api/ingest/syslog`.

- It uses Vector's plain `socket` source, not the `syslog` source, so the backend gets the
  untouched line plus the sender IP: `{"message": "<134>Oct 12 ...", "host": "10.0.1.5"}`.
  All parsing happens in the unit-tested Python normalizers.
- The backend chooses the tenant from the sender IP (`SYSLOG_TENANT_MAP`, else `DEFAULT_TENANT`),
  and firewall vs network from the content (an allow/deny `action` plus addresses means firewall).
- Each request carries `X-Ingest-Token: $SYSLOG_INGEST_TOKEN`. Caddy also returns 404 for
  `/api/ingest/syslog` from outside, so only Vector, on the Docker network, can reach it.
- If the backend is down, Vector retries, so messages are not lost during short outages.

Try it: `./samples/send_syslog.sh`, or by hand:
```
echo "<132>$(date -u '+%b %e %H:%M:%S') fw01 action=deny src=203.0.113.45 dst=10.0.0.10 dpt=22" | nc -u -w1 127.0.0.1 514
```
Port 514 is published on IPv4 at `SYSLOG_BIND` (default `0.0.0.0`; use `127.0.0.1` to keep it off
a public network). Use `127.0.0.1` rather than `localhost`, which may resolve to IPv6 first.

Note: with Docker Desktop (Mac/Windows), the sender IP that Vector sees is Docker's gateway, not
the real device, so every message gets `DEFAULT_TENANT`. On a Linux VM the real sender IP is kept.
