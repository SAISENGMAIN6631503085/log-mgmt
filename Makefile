# Thin wrappers around docker compose so reviewers only need `make <target>`.
COMPOSE := docker compose

.PHONY: up down seed test logs ps health

# Create .env from the example on first run so `make up` works out of the box
.env:
	cp .env.example .env
	@echo "Created .env from .env.example - change the secrets before deploying."

up: .env
	$(COMPOSE) up -d --build --wait
	@$(MAKE) --no-print-directory health

down:
	$(COMPOSE) down

seed: .env
	$(COMPOSE) exec backend python -m app.seed

# Tests live in /tests at the repo root (assignment layout), so mount them into the backend image.
# `python -m` puts /app on sys.path so tests can `import app`.
test: .env
	$(COMPOSE) run --rm --no-deps -v $(CURDIR)/tests:/app/tests backend python -m pytest -q tests

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps

# -k because appliance mode uses Caddy's self-signed CA
health:
	@curl -sk --retry 10 --retry-delay 1 --retry-all-errors https://localhost/health; echo
