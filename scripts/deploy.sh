#!/usr/bin/env bash
# Run on the SaaS server by the CD job. The deploy SSH key is restricted to this script
# (command="..." in authorized_keys), so GitHub can redeploy but can't open a shell.
set -euo pipefail
cd "$(dirname "$0")/.."

# --ff-only: never merge or overwrite local changes on the server; fail loudly instead.
git pull --ff-only
make up
# Each rebuild leaves the previous images behind; the server has a small disk.
docker image prune -f >/dev/null
echo "deployed $(git log --oneline -1)"
