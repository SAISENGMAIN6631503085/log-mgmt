# Setup: Appliance mode (single VM, Docker Compose)

Everything runs on one machine on your network: a laptop, a server or a VM (Ubuntu 22.04/24.04,
x86-64 or ARM). Devices on the LAN send syslog to it; people open `https://<vm-address>`.

## 1. Requirements

- The assignment's minimum appliance: **Ubuntu 22.04+, 4 vCPU, 8 GB RAM, 40 GB disk**, with ports 80/443/514 open.
  (The stack itself idles at well under 1 GB RAM, so a smaller VM works for a quick try.)
- Docker Engine with the Compose plugin, git, make, python3 (for the demo scripts).

On Ubuntu:
```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git make python3
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER   # then log out and back in
```
On macOS or Windows, install Docker Desktop instead.

## 2. Get the code and configure

```bash
git clone <your-repo-url> log-mgmt && cd log-mgmt
cp .env.example .env
```

Edit `.env`. At minimum, change the secrets:

| Variable | Set to |
|----------|--------|
| `POSTGRES_PASSWORD` | any long random string |
| `JWT_SECRET` | `openssl rand -hex 32` (the backend and ingest service refuse to start with the example value) |
| `SYSLOG_INGEST_TOKEN` | `openssl rand -hex 32` |
| `SEED_ADMIN_PASSWORD`, `SEED_VIEWER_PASSWORD` | passwords for the demo users |
| `SEED_API_KEYS` | `demoA=<key>,demoB=<key>`, ingest keys for the demo tenants |
| `SITE_ADDRESS` | `localhost`, or the VM's hostname or IP, e.g. `192.168.1.50` |
| `CADDY_TLS` | `internal` (self-signed; see step 5) |
| `SYSLOG_TENANT_MAP` | which device networks belong to which tenant, e.g. `10.0.1.0/24=demoA,10.0.2.0/24=demoB` |

Every variable is explained in `.env.example`.

## 3. Start

```bash
make up      # build, start, wait until healthy, print /health
make seed    # create users admin / viewerA / viewerB and the demo API keys
make demo    # load all sample logs (syslog + JSON API + file upload)
```

`make up` ends with `{"status":"ok","database":"ok"}`. Open `https://<SITE_ADDRESS>` and sign in as
`admin` with `SEED_ADMIN_PASSWORD`.

For live traffic with an attack every 2 minutes: `make simulate` (Ctrl-C stops it).

## 4. Send real logs

| Source | How |
|--------|-----|
| Firewalls / switches | Point their syslog at `<vm-address>`, port **514**, UDP or TCP. Key=value format works best (FortiGate, PAN-OS and Cisco-style lines are understood). The tenant comes from the device's IP via `SYSLOG_TENANT_MAP`. |
| Applications | `POST https://<vm>/api/ingest` with header `X-API-Key`; body is one JSON event or an array. |
| AWS / M365 / AD / CrowdStrike exports | `POST https://<vm>/api/ingest/file` with form fields `source` and `file` (.json, .ndjson, .csv). |

Test syslog from another machine: `./samples/send_syslog.sh -h <vm-address>`.

Open these ports in the VM firewall: **443/tcp** (and 80/tcp for the redirect) for users, and
**514/udp+tcp** from the device networks only.

## 5. The browser certificate warning

With `CADDY_TLS=internal`, Caddy issues its own certificate, because Let's Encrypt can't issue
one for `localhost` or private IPs. Traffic is encrypted, but browsers don't know the issuer and
show a warning. Either click through it, or trust Caddy's root once on each computer:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt
# Ubuntu
sudo cp caddy-root.crt /usr/local/share/ca-certificates/caddy-local.crt && sudo update-ca-certificates
```

Firefox has its own certificate store: add the file under *Settings → Certificates*. Don't commit
`caddy-root.crt`. The CA is kept in the `caddy_data` volume, so it survives restarts.

## 6. Day-to-day

| Task | Command |
|------|---------|
| Logs of all services | `make logs` |
| Status | `make ps` |
| Run tests | `make test` |
| Stop / start | `make down` / `make up` (data is kept in Docker volumes) |
| Drop old days of events now | `make retention` (also runs hourly) |
| Update | `git pull && make up` (new migrations apply automatically) |
| Backup | `docker compose exec -T postgres sh -c 'pg_dump -U $POSTGRES_USER $POSTGRES_DB' > backup.sql` |
| Restore | `docker compose exec -T postgres sh -c 'psql -U $POSTGRES_USER $POSTGRES_DB' < backup.sql` |
| Delete everything, including data | `docker compose down -v` |

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `make up` hangs or fails | `docker compose logs backend ingest`. A weak `JWT_SECRET` stops both on purpose. |
| Syslog doesn't show up | `docker compose logs vector`; is port 514 open in the firewall? Was the timestamp within the last 7 days? |
| Syslog lands in the wrong tenant | `SYSLOG_TENANT_MAP`. With Docker Desktop (Mac/Windows) every sender appears as Docker's gateway IP, so all syslog goes to `DEFAULT_TENANT`. On Linux the real IP is kept. |
| Events "rejected … retention window" | The event is older than `RETENTION_DAYS`. The demo scripts move sample timestamps to now; for your own files use recent data. |
| Port 80/443/514 already in use | Stop the other service, or change the left side of the port mapping in `docker-compose.yml`. |
