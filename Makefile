# Thin wrappers around docker compose so reviewers only need `make <target>`.
COMPOSE := docker compose

.PHONY: up down seed test logs ps health retention demo simulate

# Create .env from the example on first run so `make up` works out of the box. Secrets get
# fresh random values (the backend refuses the example JWT_SECRET, and no two installs should
# share secrets). sed -i.bak works with both GNU and BSD/macOS sed.
.env:
	cp .env.example .env
	@for var in POSTGRES_PASSWORD JWT_SECRET SYSLOG_INGEST_TOKEN; do \
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
# `python -m` puts /app on sys.path so tests can `import app`.
test: .env
	$(COMPOSE) run --rm --no-deps -v $(CURDIR)/tests:/app/tests -v $(CURDIR)/samples:/app/samples:ro backend python -m pytest -q tests

# Drop event partitions older than RETENTION_DAYS now (the backend also does this hourly)
retention: .env
	$(COMPOSE) exec backend python -m app.retention

# Load every sample (timestamps moved to "now") through syslog, the JSON API and file upload
demo: .env
	./samples/send_syslog.sh
	python3 samples/post_logs.py --key lm_demoA_dev_key_change_me
	python3 samples/post_logs.py --key lm_demoB_dev_key_change_me --mode file

# Live traffic for both demo tenants, with a brute-force attack every 2 minutes (Ctrl-C to stop)
simulate:
	python3 samples/simulator.py

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps

# -k because appliance mode uses Caddy's self-signed CA
health:
	@curl -sk --retry 10 --retry-delay 1 --retry-all-errors https://localhost/health; echo
