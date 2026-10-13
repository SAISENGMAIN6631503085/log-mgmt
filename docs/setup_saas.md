# Setup: SaaS mode (public cloud VM with an HTTPS URL)

Live demo: **https://14.207.143.101.sslip.io** (a 1 vCPU / 2 GB Ubuntu 24.04 VPS, set up exactly
as below).

The same `docker-compose.yml` runs on a public VM, and Caddy gets a real Let's Encrypt
certificate for your domain automatically. The only difference from appliance mode is a few lines
in `.env`.

## 1. Create a VM

Any provider works: AWS EC2, Google Cloud, Azure, Hetzner, DigitalOcean or Oracle Cloud's
always-free ARM VM. All images are multi-arch, so x86-64 and ARM both run unchanged.

- Ubuntu 22.04 or 24.04, 2 vCPU, 4 GB RAM, 20+ GB disk. A demo runs on **1 vCPU / 2 GB** too: the stack
  uses about 600 MB. Building the images needs more, so add 2 GB of swap first:
  `fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo '/swapfile none swap sw 0 0' >> /etc/fstab`
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

**No domain? Use sslip.io.** `<ip>.sslip.io` (e.g. `14.207.143.101.sslip.io`) already resolves to
that IP: no sign-up and nothing to configure, and Let's Encrypt issues certificates for it. Set
`SITE_ADDRESS` to that name. DuckDNS and similar services work too.

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

Use **strong, unique** values for every password, key and secret. This server is public. For example:
```bash
r() { openssl rand -base64 24 | tr -d '/+='; }
sed -i "s|^SEED_ADMIN_PASSWORD=.*|SEED_ADMIN_PASSWORD=$(r)|; s|^SEED_VIEWER_PASSWORD=.*|SEED_VIEWER_PASSWORD=$(r)|" .env
sed -i "s|^SEED_API_KEYS=.*|SEED_API_KEYS=demoA=lm_demoA_$(openssl rand -hex 16),demoB=lm_demoB_$(openssl rand -hex 16)|" .env
```
(`make up` already randomises `POSTGRES_PASSWORD`, `JWT_SECRET` and `SYSLOG_INGEST_TOKEN` when it creates `.env`.)

Harden the VM itself, too: SSH keys only, plus a host firewall:
```bash
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' \
  | sudo tee /etc/ssh/sshd_config.d/10-keys-only.conf && sudo systemctl reload ssh   # after your key works!
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw --force enable
```
Docker-published ports bypass ufw, which is why `SYSLOG_BIND=127.0.0.1` is what keeps 514 off the internet.

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

**Keep the demo looking alive** (optional): add `COMPOSE_PROFILES=demo` to `.env` and `make up`.
A small simulator service then sends realistic traffic for both demo tenants, busier by day, with an
attack every 15 minutes (brute force, port scan or malware, in turn), so reviewers always find fresh charts and alerts.

Load demo data: `make demo` on the server (it uses `SITE_ADDRESS` and the keys from `.env`), or from
your laptop against the public URL:
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

## 7. Continuous deployment

`.github/workflows/ci.yml` runs the tests and the frontend build on every push. When they pass on
`main`, its `deploy` job SSHes to the server, which runs [`scripts/deploy.sh`](../scripts/deploy.sh):
`git pull --ff-only && make up`. The site is down for a few seconds while containers restart.

One-time setup:
```bash
# 1. A key just for deploys (no passphrase), separate from your personal key.
ssh-keygen -t ed25519 -N "" -C github-deploy -f deploy_key

# 2. On the server, allow it to run deploy.sh and nothing else (no shell, no forwarding).
echo "command=\"/root/log-mgmt/scripts/deploy.sh\",restrict $(cat deploy_key.pub)" \
  | ssh root@<server> 'cat >> ~/.ssh/authorized_keys'

# 3. GitHub repository secrets
gh secret set DEPLOY_HOST --body "<server IP or name>"
gh secret set DEPLOY_SSH_KEY < deploy_key
ssh-keyscan <server> 2>/dev/null | gh secret set DEPLOY_KNOWN_HOSTS

rm deploy_key deploy_key.pub   # GitHub keeps the only copy it needs
```

Without these secrets (e.g. in a fork) the deploy job skips itself. To stop auto-deploys, delete the
`DEPLOY_SSH_KEY` secret or remove the key's line from the server's `authorized_keys`.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Caddy log: `challenge failed` / `NXDOMAIN` | DNS doesn't point at the VM yet, or port 80 is blocked |
| `too many certificates` | Let's Encrypt rate limit after many failed tries; fix DNS/ports and wait, or test with `SITE_ADDRESS` on a subdomain |
| Site works over IP but not the domain | `SITE_ADDRESS` must exactly match the domain users type |
| `make up` is killed / the build hangs on a small VM | out of memory: add swap (step 1) |
| macOS: `TLSV1_ALERT_INTERNAL_ERROR` from the sample scripts | the system Python is linked to an old LibreSSL; run the scripts on the server (`make demo`), or use a Homebrew/python.org Python |
