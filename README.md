# BCord (infra + app)

## Layout
- `docker-compose.yml` – Caddy (HTTPS), bcord (backend), Postgres, Redis
- `caddy/` – baked Caddy image (`config.json` with ACME + headers + routes)
- `app/` – C++ Boost.Beast HTTP server

## Deploy
- Backend: `cd /srv/bcord && docker compose build bcord && docker compose up -d bcord`
- Infra:   `cd /srv/bcord && docker compose build caddy && docker compose up -d caddy`

## Endpoints (via Caddy/HTTPS)
- `/api/health` – `ok`
- `/api/version` – `{"version":"…"}`
- `/api/info` – `{"name":"BCord","version":"…","build_time":"…"}`
- `/api/diag` – TCP checks for Postgres/Redis
- `/api/dbtime` – `{"db_time":"…"}`
- `/ws` – WebSocket echo (if enabled)

## Drain testing / recovery flow

- Enable draining for manual 503 testing: `docker compose kill -s TERM bcord`
- Clear the drain and start a fresh process (preferred): `docker compose restart bcord`
- Alternative drain reset flows:
  - `docker compose stop bcord && docker compose up -d bcord`
  - `docker compose up -d --force-recreate bcord`
- Compose settings already include `stop_signal: SIGTERM`, `stop_grace_period: 25s`, and a healthcheck for `http://localhost:9000/api/ready`.

## Backup / Restore (Postgres)
- Backup:  `docker compose exec -T postgres pg_dump -U bcord bcord | gzip > ~/bcord_backup_$(date +%F_%H%M).sql.gz`
- Restore: `gunzip -c ~/bcord_backup_YYYY-MM-DD_HHMM.sql.gz | docker compose exec -T postgres psql -U bcord -d bcord`

