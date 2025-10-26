#!/usr/bin/env bash
set -euo pipefail
cd /srv/bcord

BACKUP_DIR="${BACKUP_DIR:-$HOME/backups/bcord}"
LATEST="$(ls -t "$BACKUP_DIR"/bcord_backup_*.sql.gz 2>/dev/null | head -1 || true)"

if [[ -z "${LATEST}" ]]; then
  echo "No backups in $BACKUP_DIR"
  exit 1
fi

echo "Restoring from: $LATEST"
gunzip -c "$LATEST" \
  | docker compose exec -T -e PGPASSWORD=change_me postgres \
      psql -U bcord -d bcord
echo "Restore complete."

