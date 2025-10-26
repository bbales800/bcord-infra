#!/usr/bin/env bash
# ───────────────────────────────────────────────────────────────
#  BCord Frontend Deployment Script
#  Builds the React client and redeploys it via Caddy
# ───────────────────────────────────────────────────────────────

set -e  # Exit immediately if a command fails
set -o pipefail

PROJECT_ROOT="/srv/bcord"
CLIENT_DIR="${PROJECT_ROOT}/bcord-client"
SITE_DIR="${PROJECT_ROOT}/site"

echo "🚀 Starting BCord frontend deployment..."
echo "========================================="

# 1️⃣  Pull latest code
echo "📥 Syncing code with GitHub..."
cd "$PROJECT_ROOT"

# Stage and commit any local edits automatically
if [ -n "$(git status --porcelain)" ]; then
  echo "💾 Committing local changes before deploy..."
  git add -A
  git commit -m "Auto-commit before deploy on $(date '+%Y-%m-%d %H:%M:%S')"
  echo "⬆️  Pushing local commits to GitHub..."
  git push origin main
else
  echo "✅ No local changes to commit."
fi

# Pull remote updates
echo "🔄 Pulling latest changes from GitHub..."
git pull --rebase

# 2️⃣  Build frontend
echo "🏗️  Building Vite React frontend..."
cd "$CLIENT_DIR"
npm install --silent
npm run build

# 3️⃣  Copy built files to site folder
echo "📦 Copying build output to ${SITE_DIR}..."
sudo rm -rf "${SITE_DIR:?}"/*
sudo cp -a "${CLIENT_DIR}/dist/." "$SITE_DIR/"

# 4️⃣  Restart Caddy
echo "🔁 Restarting Caddy container..."
cd "$PROJECT_ROOT"
docker compose restart caddy

# 5️⃣  Success message
echo "✅ Deployment complete!"
# 6️⃣  Log deployment time
echo "$(date '+%Y-%m-%d %H:%M:%S') - Deploy completed successfully" | sudo tee -a /srv/bcord/deploy.log >/dev/null
echo "🌐 Visit: https://www.b-cord.run.place"

