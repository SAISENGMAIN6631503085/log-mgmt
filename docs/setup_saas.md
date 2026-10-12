# Setup: SaaS mode (public cloud VM with an HTTPS URL)

The same `docker-compose.yml` runs on a public VM, and Caddy gets a real Let's Encrypt
certificate for your domain automatically. The only difference from appliance mode is a few lines
in `.env`.

## 1. Create a VM

Any provider works: AWS EC2, Google Cloud, Azure, Hetzner, DigitalOcean or Oracle Cloud's
always-free ARM VM. All images are multi-arch, so x86-64 and ARM both run unchanged.

- Ubuntu 22.04 or 24.04, 2 vCPU, 4 GB RAM, 20+ GB disk
- A **static/public IP**
- Cloud firewall / security group:

| Port | From | Why |
|------|------|-----|
| 22/tcp | your IP only | SSH |
| 80/tcp | anywhere | Let's Encrypt HTTP challenge and redirect to HTTPS |
| 443/tcp | anywhere | the app |
| 514/udp+tcp | **only your devices' public IPs**, or closed | syslog has no authentication; never open it to the whole internet |

## 2. Point a domain at it

Create a DNS **A record** (and AAAA if you have IPv6), e.g. `logs.example.com → <VM public IP>`.
Wait until `dig +short logs.example.com` returns the IP. Let's Encrypt checks DNS before it issues
a certificate.

No domain? A free DNS name from services like DuckDNS works the same way.

## 3. Install and configure

```bash
sudo apt-get update && sudo apt-get install -y git make python3
curl -fsSL https://get.docker.com | sudo sh && sudo usermod -aG docker $USER   # re-login after
git clone <your-repo-url> log-mgmt && cd log-mgmt
cp .env.example .env
```

In `.env`, set the secrets exactly as in [appliance step 2](setup_appliance.md#2-get-the-code-and-configure),
then the SaaS-specific values:

```ini
SITE_ADDRESS=logs.example.com      # your DNS name
CADDY_TLS=you@example.com          # an email -> Caddy uses Let's Encrypt (expiry notices go here)
SYSLOG_BIND=127.0.0.1              # syslog off from the internet (or keep 0.0.0.0 with the firewall rule above)
```

Use **strong, unique** values for every password, key and secret. This server is public.

## 4. Start

```bash
make up && make seed
```

Watch the certificate being issued: `docker compose logs -f caddy`, then look for
`certificate obtained successfully`. Then:

```bash
curl https://logs.example.com/health          # no -k needed: the certificate is real
```

Open `https://logs.example.com` and sign in. No browser warning.

Load demo data from your laptop against the public URL:
```bash
python3 samples/post_logs.py --url https://logs.example.com --verify-tls --key <demoA key from .env>
python3 samples/simulator.py --url https://logs.example.com --verify-tls --no-syslog --keys <keyA>,<keyB>
```

## 5. How the two modes differ

| | Appliance | SaaS |
|---|---|---|
| `SITE_ADDRESS` | `localhost` / LAN IP | public DNS name |
| `CADDY_TLS` | `internal` (Caddy's own CA) | email address (Let's Encrypt, auto-renewed) |
| Browser warning | yes, until Caddy's root is trusted | no |
| `SYSLOG_BIND` | `0.0.0.0` (LAN devices) | `127.0.0.1`, or firewall-restricted |
| Everything else | identical | identical |

## 6. Operating it

- **Renewal**: Caddy renews certificates by itself. Certificates live in the `caddy_data`
  volume, so restarts don't hit Let's Encrypt rate limits.
- **Updates**: `git pull && make up`. Migrations run on startup.
- **Backups**: schedule the `pg_dump` command from the appliance guide (e.g. with cron) and copy
  the file off the VM, for example to object storage.
- **Logs**: `make logs`. Restarts: every service has `restart: unless-stopped`, so they also
  come back after a reboot.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Caddy log: `challenge failed` / `NXDOMAIN` | DNS doesn't point at the VM yet, or port 80 is blocked |
| `too many certificates` | Let's Encrypt rate limit after many failed tries; fix DNS/ports and wait, or test with `SITE_ADDRESS` on a subdomain |
| Site works over IP but not the domain | `SITE_ADDRESS` must exactly match the domain users type |
