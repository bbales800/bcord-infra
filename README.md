# BCord — Backend + Infra (Caddy • Boost.Beast • Postgres • Redis)

## Overview
- **Caddy** terminates TLS on `:443` and serves static `caddy/index.html`.
- **Backend** (C++/Boost.Beast) listens on `:9000` inside the Docker network only.
- **Postgres 16** + **Redis 7** as services with persisted volumes.
- Traffic:
  - `https://b-cord.run.place/` → static page
  - `https://b-cord.run.place/api/*` → backend HTTP
  - `wss://b-cord.run.place/ws` (and `/api/ws`) → backend WebSocket echo

## Layout

