#!/usr/bin/env bash
set -euo pipefail
cd /srv/bcord
docker compose build caddy
docker compose up -d caddy
docker compose logs --tail=20 caddy

