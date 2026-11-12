# Farrier production stack (Docker Compose)

`production.yml` runs Farrier on one Docker host with high availability for the engine process,
PostgreSQL, and S3-compatible object storage. For a quick single-container trial, use the root
`docker-compose.yml` instead.

| Service | What it does | Hardening |
| --- | --- | --- |
| `engine` ×2 | API + renewal loop; one replica holds the PostgreSQL leader lock | read-only root, `cap_drop: ALL`, `no-new-privileges`, UID 10001, tmpfs for `/tmp` and `/data`, healthcheck |
| `web` | Dashboard, on `127.0.0.1:3000` only | same as the engine |
| `postgres` | PostgreSQL 16, data on the `postgres-data` volume, SCRAM auth | `no-new-privileges`, internal network only |
| `minio` | S3-compatible storage for change packs, backups and audit exports | `no-new-privileges`, console off, internal network only |
| `minio-init` | One-shot: bucket `farrier`, versioning, lifecycle (change packs 30 days, old versions 90), a `farrier-engine` user limited to `farrier/farrier/*` | |

Networks: `backend` is `internal: true` (database, storage, engine API: no route out); the engine
also joins `egress` (ACME CAs, DNS APIs, your devices); the web app joins `frontend` (published port,
OIDC issuer).

## Secrets

Secrets are Docker secrets: files under `deploy/compose/secrets/`, bind-mounted read-only at
`/run/secrets/`. Nothing secret is in the compose file or in `docker inspect`. Variables the images
read from the environment are exported from `/run/secrets/<VAR_NAME>` by a two-line entrypoint;
`FARRIER_DATABASE_PASSWORD` uses the engine's native `file:` reference.

```bash
cd deploy/compose
install -d -m 0700 secrets
openssl rand -hex 32 > secrets/api_token
openssl rand -hex 32 > secrets/api_read_token
openssl rand -hex 16 > secrets/dashboard_password
openssl rand -hex 32 > secrets/db_password
printf farrier-admin > secrets/minio_root_user
openssl rand -hex 32 > secrets/minio_root_password
openssl rand -hex 32 > secrets/minio_engine_secret
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode(), end='')" > secrets/master_key
# strip trailing newlines (the shell export keeps them otherwise)
for f in secrets/*; do printf %s "$(cat "$f")" > "$f"; done
chmod 0444 secrets/*      # the containers run as non-root users and must read them
```

Back up `secrets/master_key` separately from the database backups: a backup without its key
cannot be decrypted, which is the point.

## Run

```bash
NEXT_PUBLIC_SITE_URL=https://farrier.example.internal \
  docker compose -f deploy/compose/production.yml up -d
docker compose -f deploy/compose/production.yml ps
```

Put a TLS-terminating reverse proxy (Caddy, nginx, Traefik, your load balancer) in front of
`127.0.0.1:3000`. It must append to or overwrite `X-Forwarded-For` (Caddy and Traefik do; nginx:
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`), never pass the client's value
through unchanged. `FARRIER_TRUSTED_PROXY_HOPS` is `1` for that one proxy; make it `2` if a CDN or
load balancer sits in front of it. Set `FARRIER_VERSION` to pin a release; for air-gapped hosts, mirror the images
into your registry and pin them by digest.

Moving from the single-host quickstart's SQLite: `farrier db migrate --to "postgresql://..."` with
the same master key (see `/docs/databases`).

## Single sign-on

Add to `web.environment`: `FARRIER_OIDC_ISSUER`, `FARRIER_OIDC_CLIENT_ID`,
`FARRIER_OIDC_REDIRECT_URI` (required in production: `<NEXT_PUBLIC_SITE_URL>/auth/callback`, registered
exactly with the identity provider), and optionally `FARRIER_OIDC_SCOPES` and group settings; add `oidc_client_secret` and `session_secret` files and mount them on `web` with
targets `FARRIER_OIDC_CLIENT_SECRET` and `FARRIER_SESSION_SECRET`. Remove `dashboard_password`.

## Object storage

The engine gets `FARRIER_STORAGE_URL=s3://farrier/farrier` and
`FARRIER_STORAGE_S3_ENDPOINT=http://minio:9000`, with S3 credentials as the standard
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` variables (the secret from `minio_engine_secret`).
MinIO's community edition no longer publishes new images; the pinned release works, and any
S3-compatible store (Ceph RGW, SeaweedFS, Garage, a NetApp or Dell S3 endpoint) can replace it: point
`FARRIER_STORAGE_S3_ENDPOINT` at it and drop the `minio` services. Only the `farrier-engine` user
(and the MinIO root user) can write the bucket, which holds backups: keep it that way, since
`farrier restore` trusts a backup's rows (backups are HMAC-signed; unsigned ones need
`--allow-unsigned`).

## Device credentials

Mount device credentials read-only under `/run/secrets/farrier/` on the engine (another Docker
secret per credential, with `target: farrier/<name>`) and reference them as
`file:/run/secrets/farrier/<name>`, or set `FARRIER_SECRET_BACKEND=hashicorp` (see the comment at the
top of `production.yml`).

## Database TLS

The engine reaches PostgreSQL over the internal `backend` network with `sslmode=prefer`. If the
database runs on another host, enable TLS on it and switch to
`sslmode=verify-full&sslrootcert=/run/secrets/db_ca` with the CA as a Docker secret.

## Checks

```bash
docker compose -f deploy/compose/production.yml config -q   # also run in CI
```
