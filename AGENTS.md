# BCord Operations Runbook

This repository lives at `/srv/bcord` on the Rumble Cloud VM (Ubuntu 24.04). It contains the Docker-based deployment for the BCord stack.

## 0. Shared context
- **Reverse proxy:** Caddy on ports 80/443 → https://b-cord.run.place
- **Backend:** C++ Boost.Beast service on port 9000 (Docker service `bcord`)
- **Data stores:** PostgreSQL 16, Redis 7
- **Key endpoints (via Caddy):**
  - Health: `/api/health` (liveness), `/api/ready` (readiness)
  - Info: `/api/info`, `/api/version`, `/api/dbtime`, `/api/diag`
  - Chat WS: `wss://b-cord.run.place/ws?channel=<name>&user=<name>&ts=<unix>&token=<hmac>`
  - History & Presence: `/api/history`, `/api/presence`
  - Dev helpers (require `ENABLE_DEV_TOKEN=1`): `/api/login`, `/api/attachments/presign`, `/api/adminsig*`
- **Abuse controls:** HTTP per-IP rate limit (20 token burst ≈10 rps), 10 s recv timeout, WS message cap 4 KiB (1009), WS rate ≤30 msgs/10 s (1008)
- **Scaling:** Redis pub/sub fan-out with instance dedupe via `INSTANCE_ID`
- **Readiness:** Requires DB ok and Redis subscriber healthy; `/api/ready` returns 503 while draining

## 1. Deploy agent (backend)
```bash
cd /srv/bcord
docker compose build bcord
docker compose up -d bcord
docker compose logs --tail=60 bcord
docker compose ps    # `bcord-backend` should become "healthy"
```
Verify readiness:
```bash
curl -sS https://b-cord.run.place/api/ready | jq .
# {"ready":true,"db":true,"redis_sub":true}
```

## 2. Drain agent (graceful rolling)
Start drain to block new WS connections but keep existing ones temporarily:
```bash
docker compose kill -s TERM bcord
curl -i -sS https://b-cord.run.place/api/ready | sed -n '1,3p'  # expect HTTP/2 503
```
Active WebSocket sessions close after `DRAIN_CLOSE_AFTER_SECONDS` (default 20 s) with code 1001.

Clear drain:
```bash
docker compose restart bcord
curl -i -sS https://b-cord.run.place/api/ready | sed -n '1,3p'  # expect HTTP/2 200
```

## 3. Redis fan-out agent (multi-instance validation)
```bash
# Terminal A: subscribe
docker compose exec -T redis redis-cli SUBSCRIBE bcord:general

# Terminal B: publish via WS
RESP=$(curl -s "https://b-cord.run.place/api/login?user=Bryan&channel=general")
TOKEN=$(jq -r .token <<<"$RESP"); TS=$(jq -r .ts <<<"$RESP")
printf 'pubsub-test\n' | docker run --rm -i ghcr.io/vi/websocat:latest \
  "wss://b-cord.run.place/ws?channel=general&user=Bryan&ts=$TS&token=$TOKEN"
```
Expect a JSON message on `bcord:general` in terminal A.

## 4. Attachments agent (S3/MinIO presigned PUT)
1. Obtain S3-compatible credentials (`S3_ACCESS_KEY`, `S3_SECRET_KEY`) from AWS, MinIO, or another provider.
2. Configure `/srv/bcord/.env` (auto-loaded by Compose). Examples:
   - **AWS S3 (virtual-hosted):**
     ```bash
     S3_ENDPOINT=s3.amazonaws.com
     S3_BUCKET=bcord-attachments
     S3_REGION=us-east-1
     S3_ACCESS_KEY=<AWS_ACCESS_KEY_ID>
     S3_SECRET_KEY=<AWS_SECRET_ACCESS_KEY>
     S3_USE_SSL=1
     S3_VIRTUAL_HOSTED=1
     S3_PRESIGN_TTL_SECONDS=600
     S3_PUBLIC_BASE_URL=
     ```
   - **MinIO / path-style:**
     ```bash
     S3_ENDPOINT=<host-or-ip>
     S3_BUCKET=bcord-attachments
     S3_REGION=us-east-1
     S3_ACCESS_KEY=<YOUR_MINIO_ACCESS_KEY>
     S3_SECRET_KEY=<YOUR_MINIO_SECRET_KEY>
     S3_USE_SSL=0|1
     S3_VIRTUAL_HOSTED=0
     S3_PRESIGN_TTL_SECONDS=600
     S3_PUBLIC_BASE_URL=
     ```
   Ensure `.env` is git-ignored:
   ```bash
grep -q '^\.env$' .gitignore || echo ".env" | sudo tee -a .gitignore
   ```
3. Restart backend: `docker compose up -d bcord`
4. (MinIO) create bucket: `mc mb local/bcord-attachments`
5. (Optional) configure CORS for PUT/GET.
6. Test presign + PUT:
   ```bash
   P=$(curl -sS "https://b-cord.run.place/api/attachments/presign?channel=general&filename=readme.txt&content_type=text/plain")
   PUT_URL=$(echo "$P" | jq -r .url)
   HDR_CT=$(echo "$P" | jq -r '.headers["Content-Type"] // empty')
   GET_URL=$(echo "$P" | jq -r '.get_url // empty')
   if [ -n "$HDR_CT" ]; then
     curl -sS -X PUT -H "Content-Type: $HDR_CT" -T README.md "$PUT_URL" -D -
   else
     curl -sS -X PUT -T README.md "$PUT_URL" -D -
   fi
   curl -sS "$GET_URL" | head -n 3
   ```

Troubleshooting:
- `curl: (6) Could not resolve host` → use path-style (`S3_VIRTUAL_HOSTED=0`).
- `403 SignatureDoesNotMatch` → check keys/region/bucket (`docker compose exec bcord env | grep '^S3_'`).
- `403 AccessDenied` → verify IAM policy or bucket.
- `AuthorizationHeaderMalformed` → region mismatch.
- `RequestTimeTooSkewed` → sync VM clock.

## 5. History/Presence agent (HTTP)
```bash
curl -s "https://b-cord.run.place/api/history?channel=general&limit=3" | jq .
curl -s "https://b-cord.run.place/api/presence?channel=general" | jq .
```

## 6. DB agent (backup/restore)
- Automated backup: `/srv/bcord/scripts/db-backup.sh`
- Manual backup:
  ```bash
  docker compose exec -T postgres pg_dump -U bcord bcord | gzip > ~/bcord_backup_$(date +%F_%H%M).sql.gz
  ```
- Restore latest script: `/srv/bcord/app/db-restore-latest.sh` (if present)
- Manual restore:
  ```bash
gunzip -c ~/bcord_backup_YYYY-MM-DD_HHMM.sql.gz | docker compose exec -T postgres psql -U bcord -d bcord
  ```

## 7. Diagnostics agent
```bash
curl -sS https://b-cord.run.place/api/diag | jq .
curl -sS https://b-cord.run.place/api/dbtime | jq .
docker compose logs --tail=120 bcord | sed -n '1,200p'
```

## 8. Security agent
- Dev endpoints require `ENABLE_DEV_TOKEN=1`; disable in production.
- Keep `S3_*` secrets in `.env`/secrets manager; never commit credentials.
- Health checks should target `/api/ready` (returns 503 while draining).

## 9. Quick cheat-sheet
```bash
# WS token + send
RESP=$(curl -s "https://b-cord.run.place/api/login?user=Bryan&channel=general"); \
TOKEN=$(jq -r .token <<<"$RESP"); TS=$(jq -r .ts <<<"$RESP"); \
printf 'hi\n' | docker run --rm -i ghcr.io/vi/websocat:latest \
"wss://b-cord.run.place/ws?channel=general&user=Bryan&ts=$TS&token=$TOKEN"

# Drain toggle
docker compose kill -s TERM bcord
docker compose restart bcord

# Presign + PUT (path-style)
P=$(curl -sS "https://b-cord.run.place/api/attachments/presign?channel=general&filename=readme.txt&content_type=text/plain")
PUT_URL=$(echo "$P" | jq -r .url); HDR_CT=$(echo "$P" | jq -r '.headers["Content-Type"] // empty')
[ -n "$HDR_CT" ] && CT="-H Content-Type: $HDR_CT" || CT=''
curl -sS -X PUT $CT -T README.md "$PUT_URL" -D -
```

> **Note:** Ensure outbound TCP/443 is allowed for your S3/MinIO endpoint. For local MinIO on the VM: set `S3_ENDPOINT=127.0.0.1:9000`, `S3_USE_SSL=0`, `S3_VIRTUAL_HOSTED=0`, and open the firewall if external access is required. Virtual-hosted style needs wildcard DNS; prefer path-style until DNS is ready.
