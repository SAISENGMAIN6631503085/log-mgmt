# Thin wrappers around docker compose so reviewers only need `make <target>`.
COMPOSE := docker compose

# A few values from .env, so health/demo also work on a SaaS host with its own name and keys.
# Before .env exists they fall back to the appliance defaults.
env = $(shell sed -n 's/^$(1)=//p' .env 2>/dev/null)
SITE := $(or $(call env,SITE_ADDRESS),localhost)
KEY_A := $(or $(shell sed -n 's/^SEED_API_KEYS=.*demoA=\([^,]*\).*/\1/p' .env 2>/dev/null),lm_demoA_dev_key_change_me)
KEY_B := $(or $(shell sed -n 's/^SEED_API_KEYS=.*demoB=\([^,]*\).*/\1/p' .env 2>/dev/null),lm_demoB_dev_key_change_me)

.PHONY: up down seed test logs ps health retention demo simulate

# Create .env from the example on first run so `make up` works out of the box. Secrets get
# fresh random values (the backend refuses the example JWT_SECRET, and no two installs should
# share secrets). sed -i.bak works with both GNU and BSD/macOS sed.
.env:
	cp .env.example .env
	@for var in POSTGRES_PASSWORD CLICKHOUSE_PASSWORD JWT_SECRET SYSLOG_INGEST_TOKEN; do \
		sed -i.bak "s|^$$var=.*|$$var=$$(openssl rand -hex 32)|" .env; \
	done; rm -f .env.bak
	@echo "Created .env with random secrets. Review it (demo passwords, SITE_ADDRESS) before deploying."

up: .env
	$(COMPOSE) up -d --build --wait
	@# The Caddyfile is a single-file bind mount. Many editors save by replacing the file, which
	@# leaves the container looking at the old (deleted) one, so restart Caddy to re-attach it.
	@$(COMPOSE) restart caddy >/dev/null 2>&1
	@$(MAKE) --no-print-directory health

down:
	$(COMPOSE) down

seed: .env
	$(COMPOSE) exec backend python -m app.seed

# Tests live in /tests at the repo root (assignment layout), so mount them into the backend image.
# Two suites: pytest (backend, plus end to end through the running services) and go test
# (the ingest service). `python -m` puts /app on sys.path so tests can `import app`.
# faulthandler_timeout: a test still running after 2 minutes prints its stack trace.
test: .env
	$(COMPOSE) run --rm --no-deps -v $(CURDIR)/tests:/app/tests backend python -m pytest -q -o faulthandler_timeout=120 tests
	$(COMPOSE) run --rm --no-deps ingest-test

# Drop days of events older than RETENTION_DAYS now (the backend also does this hourly)
retention: .env
	$(COMPOSE) exec backend python -m app.retention

# Load every sample (timestamps moved to "now") through syslog, the JSON API and file upload
demo: .env
	./samples/send_syslog.sh
	python3 samples/post_logs.py --url https://$(SITE) --key $(KEY_A)
	python3 samples/post_logs.py --url https://$(SITE) --key $(KEY_B) --mode file

# Live traffic for both demo tenants, with an attack every 2 minutes: brute force, port scan, malware in turn (Ctrl-C to stop)
simulate:
	python3 samples/simulator.py

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps

# -k because appliance mode uses Caddy's self-signed CA. Caddy only answers TLS for SITE_ADDRESS,
# so connect to this machine but ask for that name (--resolve).
health:
	@curl -sk --retry 10 --retry-delay 1 --retry-all-errors --resolve $(SITE):443:127.0.0.1 https://$(SITE)/health; echo
