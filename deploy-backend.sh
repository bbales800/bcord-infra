#!/usr/bin/env bash
set -euo pipefail
cd /srv/bcord/app
# (optional) git pull here if you plan to push app/ to GitHub
cd /srv/bcord
docker compose build bcord
docker compose up -d bcord
docker compose logs --tail=20 bcord

