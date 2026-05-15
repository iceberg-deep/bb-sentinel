#!/usr/bin/env bash
# Minimal VPS bootstrap for bb-sentinel. Idempotent — safe to re-run.
set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")" && pwd)}"
cd "$REPO_DIR"

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing dependency: $1" >&2
        exit 1
    }
}

require docker

if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose v2 plugin is required (docker compose ...)" >&2
    exit 1
fi

if [[ ! -f config/programs.yaml ]]; then
    echo "config/programs.yaml not found — copying example. Edit before re-running." >&2
    cp config/programs.example.yaml config/programs.yaml
fi
if [[ ! -f config/global.yaml ]]; then
    cp config/global.example.yaml config/global.yaml
fi

if [[ ! -f .env ]]; then
    cat > .env <<'ENV'
POSTGRES_USER=bb
POSTGRES_PASSWORD=change_me_now
POSTGRES_DB=bb_sentinel
# Webhook URLs (set as needed):
# SLACK_WEBHOOK_EXAMPLE_PROGRAM=https://hooks.slack.com/services/...
# SLACK_WEBHOOK_ATT=https://hooks.slack.com/services/...
ENV
    echo "wrote .env — edit it before first start" >&2
fi

echo "==> building image"
docker compose build

echo "==> bringing up services"
docker compose up -d

echo "==> tailing sentinel logs (ctrl-c to detach; service keeps running)"
docker compose logs -f --tail 50 sentinel
