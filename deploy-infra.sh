#!/usr/bin/env bash
set -euo pipefail
cd /srv/bcord
# (optional) git pull here if you plan to push infra to GitHub
docker compose build caddy
docker compose up -d caddy
docker compose logs --tail=20 caddy

