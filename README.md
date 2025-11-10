# BCord (infra + app)

## Layout
- `docker-compose.yml` – Caddy (HTTPS), bcord (backend), Postgres, Redis
- `caddy/` – baked Caddy image (`config.json` with ACME + headers + routes)
- `app/` – C++ Boost.Beast HTTP server

## Deploy
- Backend: `cd /srv/bcord && docker compose build bcord && docker compose up -d bcord`
- Infra:   `cd /srv/bcord && docker compose build caddy && docker compose up -d caddy`

## Host bootstrap prerequisites

Run `sudo /srv/bcord/scripts/host-bootstrap.sh` on fresh hosts to install
diagnostic tooling (net-tools, lsof, curl, jq) and persist the Redis
recommendation `vm.overcommit_memory=1` before starting the stack.

## Attachment storage configuration

The backend issues presigned URLs so clients can upload directly to an S3-compatible
bucket. Docker Compose expects the credentials in a project-level `.env` file. If
`S3_ACCESS_KEY` is missing you will see an interpolation error when starting the
stack. Follow the steps below to obtain real credentials and surface them to the
containers.

### A. Choose your S3 provider and create access keys

#### Option 1 — AWS S3 (recommended for production)

1. In the AWS Console open **IAM → Users → Create user**.
2. Name the user (for example `bcord-uploader`), disable console access, and attach
   a custom inline policy that grants `s3:PutObject` and `s3:GetObject` on your
   bucket. Example policy targeting a bucket named `bcord-attachments`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": ["s3:PutObject", "s3:GetObject"],
         "Resource": "arn:aws:s3:::bcord-attachments/*"
       }
     ]
   }
   ```

3. After the user is created open **Security credentials → Create access key** and
   copy both the access key ID and secret access key (the secret is only shown once).
4. Note the bucket region (e.g., `us-east-1`) for use in the `.env` file.

#### Option 2 — MinIO (self-hosted, great for development)

- The root credentials you pass when starting MinIO map directly to the required
  values (`MINIO_ROOT_USER` → `S3_ACCESS_KEY`, `MINIO_ROOT_PASSWORD` →
  `S3_SECRET_KEY`).
- To provision a dedicated user instead of the root account, use `mc admin user add`
  and attach a policy that allows `s3:PutObject`/`s3:GetObject` on your bucket.

#### Option 3 — MinIO Play (public demo service)

Sign in to the Play console, create a bucket, then mint an access key pair from the
console. Play requires real credentials for write tests; placeholders such as
`changeme-access` will be rejected with HTTP 403 responses.

> **Important:** Credentials must come from your provider. They cannot be
> fabricated locally and must correspond to an account that has write access to the
> target bucket.

### B. Store the secrets in `.env`

1. Create or edit `/srv/bcord/.env` (Compose loads it automatically).
2. Add the block that matches your provider:

   **AWS S3 (virtual-hosted style):**

   ```env
   S3_ENDPOINT=s3.amazonaws.com
   S3_BUCKET=bcord-attachments
   S3_REGION=us-east-1            # replace with your real region
   S3_ACCESS_KEY=<YOUR_AWS_ACCESS_KEY_ID>
   S3_SECRET_KEY=<YOUR_AWS_SECRET_ACCESS_KEY>
   S3_USE_SSL=1
   S3_VIRTUAL_HOSTED=1
   S3_PRESIGN_TTL_SECONDS=600
   S3_PUBLIC_BASE_URL=
   ```

   **MinIO / MinIO Play (path-style until DNS is configured):**

   ```env
   S3_ENDPOINT=play.min.io        # or the host/IP of your MinIO instance
   S3_BUCKET=bcord-attachments    # ensure the bucket already exists
   S3_REGION=us-east-1
   S3_ACCESS_KEY=<YOUR_MINIO_ACCESS_KEY>
   S3_SECRET_KEY=<YOUR_MINIO_SECRET_KEY>
   S3_USE_SSL=1                   # set to 0 if MinIO is served over HTTP
   S3_VIRTUAL_HOSTED=0
   S3_PRESIGN_TTL_SECONDS=600
   S3_PUBLIC_BASE_URL=
   ```

   The repository already git-ignores `.env`, but double-check before committing
   changes that could leak secrets.

3. Restart the backend to apply the new environment:

   ```bash
   cd /srv/bcord
   docker compose up -d bcord
   ```

### C. Validate presigned uploads

Use the dev helper endpoint (requires `ENABLE_DEV_TOKEN=1`) to mint a presigned PUT
URL and upload a test file. Expect `200 OK` from AWS S3 or `204 No Content` from
MinIO when the upload succeeds.

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

[ -n "$GET_URL" ] && curl -sS "$GET_URL" | head -n 3
```

If uploads fail, re-check the keys, region, bucket name, endpoint, and time skew,
or inspect the container environment with `docker compose exec bcord env | grep -E
'^S3_'`.

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

