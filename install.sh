#!/bin/sh
# Farrier in one command, on any machine with Docker:
#   curl -fsSL https://raw.githubusercontent.com/gagankarthik/farrier/main/install.sh | sh
# Try it on a simulated estate first (kept apart from a real install):
#   curl -fsSL https://raw.githubusercontent.com/gagankarthik/farrier/main/install.sh | FARRIER_MODE=demo sh
# Settings (environment): FARRIER_DIR (default ./farrier, ./farrier-demo for the demo), FARRIER_PORT (3000),
# FARRIER_VERSION (the release, default from docker-compose.yml), FARRIER_REF (git ref of docker-compose.yml).
# Running it again keeps .env (token, password) and the data volume, and upgrades to FARRIER_VERSION.
set -eu

mode=${FARRIER_MODE:-serve}
case $mode in serve | demo) ;; *) echo "FARRIER_MODE must be serve or demo" >&2; exit 1 ;; esac
[ "$mode" = demo ] && default_dir=farrier-demo || default_dir=farrier
dir=${FARRIER_DIR:-$default_dir}
ref=${FARRIER_REF:-main}

command -v docker >/dev/null 2>&1 || { echo "Farrier needs Docker: https://docs.docker.com/get-docker/" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Farrier needs Docker Compose v2 (docker compose)" >&2; exit 1; }

mkdir -p "$dir"
cd "$dir"
curl -fsSL "https://raw.githubusercontent.com/gagankarthik/farrier/$ref/docker-compose.yml" -o docker-compose.yml

new=""
if [ ! -f .env ]; then
  rand() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
  password=$(rand 12)
  (umask 077 && {
    echo "FARRIER_API_TOKEN=$(rand 32)"
    echo "FARRIER_DASHBOARD_PASSWORD=$password"
    echo "FARRIER_MODE=$mode"
    echo "FARRIER_PORT=${FARRIER_PORT:-3000}"
  } > .env)
  new=1
fi
# a version asked for now is pinned in .env, so a later plain `docker compose up` keeps it
if [ -n "${FARRIER_VERSION:-}" ]; then
  (umask 077 && { grep -v '^FARRIER_VERSION=' .env || true; echo "FARRIER_VERSION=$FARRIER_VERSION"; } > .env.tmp)
  mv .env.tmp .env
fi
version=$(sed -n 's/^FARRIER_VERSION=//p' .env)
# shellcheck disable=SC2016  # the pattern matches the literal ${FARRIER_VERSION:-x} text in the compose file
[ -n "$version" ] || version=$(sed -n 's/.*farrier:${FARRIER_VERSION:-\([^}]*\)}.*/\1/p' docker-compose.yml | head -n 1)
if [ "$(sed -n 's/^FARRIER_MODE=//p' .env)" = demo ] && [ "$version" = 0.1.0 ]; then
  echo "The demo in Docker needs Farrier 0.2.0 or later; set FARRIER_VERSION, or try it from source:" >&2
  echo "https://github.com/gagankarthik/farrier#readme" >&2
  exit 1
fi

docker compose pull --quiet
docker compose up -d --no-build

port=$(sed -n 's/^FARRIER_PORT=//p' .env)
echo
echo "Farrier is starting: http://localhost:${port:-3000}/dashboard"
if [ -n "$new" ]; then
  echo "Sign in with the password: $password"
  echo "(saved in $(pwd)/.env with the API token; keep that file private)"
fi
echo "Logs: cd $(pwd) && docker compose logs -f    Stop: docker compose down"
echo "Back up the farrier-data volume: it holds the database and the master key."
