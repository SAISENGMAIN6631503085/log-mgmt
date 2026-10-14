#!/usr/bin/env bash
# Run on the SaaS server by the CD job. The deploy SSH key is restricted to this script
# (command="..." in authorized_keys), so GitHub can redeploy but can't open a shell.
set -euo pipefail
cd "$(dirname "$0")/.."

# --ff-only: never merge or overwrite local changes on the server; fail loudly instead.
git pull --ff-only
make up
# The simulator runs samples/simulator.py from a bind mount, so a changed script doesn't
# recreate its container; restart it to pick up the new code. No-op without the demo profile.
docker compose restart simulator >/dev/null 2>&1 || true
# Copy any events ClickHouse doesn't have yet (first deploy, or logs that arrived while it was
# down). Skips everything already there, so it's quick and safe on every deploy.
make ch-backfill
# Each rebuild leaves the previous images behind; the server has a small disk.
docker image prune -f >/dev/null
echo "deployed $(git log --oneline -1)"
