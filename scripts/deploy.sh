#!/usr/bin/env bash
# Run on the SaaS server by the CD job. The deploy SSH key is restricted to this script
# (command="..." in authorized_keys), so GitHub can redeploy but can't open a shell.
#
# Everything is inside main(), which bash reads in full before running it. `git pull` below may
# replace this very file; without the function, bash would keep reading the new file from the old
# position half-way through and skip or garble steps.
set -euo pipefail

main() {
    cd "$(dirname "$0")/.."

    # --ff-only: never merge or overwrite local changes on the server; fail loudly instead.
    before=$(git rev-parse HEAD)
    git pull --ff-only
    make up
    # ClickHouse's settings are mounted files, so changing them doesn't recreate the container.
    # Restart it only when they changed in this pull (a restart briefly pauses dashboards).
    if ! git diff --quiet "$before" HEAD -- clickhouse/; then
        docker compose restart clickhouse
        docker compose up -d --wait clickhouse
    fi
    # Same for Vector's config (a mounted file): restart it so it uses the new one.
    if ! git diff --quiet "$before" HEAD -- ingest/vector.yaml; then
        docker compose restart vector
    fi
    # The simulator runs samples/simulator.py from a bind mount, so a changed script doesn't
    # recreate its container; restart it to pick up the new code. No-op without the demo profile.
    docker compose restart simulator >/dev/null 2>&1 || true
    # Each rebuild leaves the previous images behind; the server has a small disk.
    docker image prune -f >/dev/null
    echo "deployed $(git log --oneline -1)"
}

main "$@"
