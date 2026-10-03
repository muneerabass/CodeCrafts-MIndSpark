#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

command -v go >/dev/null 2>&1 || {
  echo "Error: Go is required but was not found in PATH." >&2
  exit 1
}

command -v npm >/dev/null 2>&1 || {
  echo "Error: npm is required but was not found in PATH." >&2
  exit 1
}

# These defaults avoid the Jenkins/Postgres services commonly running on
# ports 8080/5432 on the development machine. Override them if needed.
export DEV_DB_PORT="${DEV_DB_PORT:-55432}"
export DEV_API_PORT="${DEV_API_PORT:-8081}"
export DEV_WORKER_HEALTH_PORT="${DEV_WORKER_HEALTH_PORT:-8082}"

# Read server-side database URLs from web/.env.local when they are not already
# present in the shell. The last matching entry wins, which also lets a local
# override be appended without changing existing developer settings.
env_value_file() {
  local key="$1"
  [[ -f "$ROOT_DIR/web/.env.local" ]] || return 0
  awk -F= -v key="$key" '
    {
      k = $1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
      if (k == key) {
        v = substr($0, index($0, "=") + 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
        value = v
      }
    }
    END { if (value != "") print value }
  ' "$ROOT_DIR/web/.env.local"
}

WEB_DATABASE_URL="$(env_value_file DATABASE_URL)"
WEB_DATABASE_OWNER_URL="$(env_value_file DATABASE_OWNER_URL)"
WEB_DATABASE_QUERY_URL="$(env_value_file DATABASE_QUERY_URL)"
WEB_DATABASE_URL_WEB="$(env_value_file DATABASE_URL_WEB)"
WEB_SUPERADMIN_EMAILS="$(env_value_file SUPERADMIN_EMAILS)"

export DATABASE_URL="${DATABASE_URL:-${WEB_DATABASE_URL:-postgres://depguard_app:dev@localhost:${DEV_DB_PORT}/depguard?sslmode=disable}}"
export DATABASE_OWNER_URL="${DATABASE_OWNER_URL:-${WEB_DATABASE_OWNER_URL:-postgres://depguard:dev@localhost:${DEV_DB_PORT}/depguard?sslmode=disable}}"
export DATABASE_QUERY_URL="${DATABASE_QUERY_URL:-${WEB_DATABASE_QUERY_URL:-postgres://depguard_query:dev@localhost:${DEV_DB_PORT}/depguard?sslmode=disable}}"
export DATABASE_URL_WEB="${DATABASE_URL_WEB:-${WEB_DATABASE_URL_WEB:-postgres://depguard_web:dev@localhost:${DEV_DB_PORT}/depguard_web?sslmode=disable}}"
export SERVICE_JWT_SECRET="${SERVICE_JWT_SECRET:-dev-only-service-jwt-secret-0123456789abcdef}"
export BETTER_AUTH_SECRET="${BETTER_AUTH_SECRET:-dev-only-better-auth-secret-0123456789abcdef}"
export PUBLIC_URL="${PUBLIC_URL:-http://localhost:3000}"
export PUBLIC_API_URL="${PUBLIC_API_URL:-http://localhost:${DEV_API_PORT}}"
export API_URL="${API_URL:-http://localhost:${DEV_API_PORT}}"
export BETTER_AUTH_URL="${BETTER_AUTH_URL:-http://localhost:3000}"
export TENANT_DOMAIN_SUFFIX="${TENANT_DOMAIN_SUFFIX:-localhost}"
export SUPERADMIN_EMAILS="${SUPERADMIN_EMAILS:-${WEB_SUPERADMIN_EMAILS:-admin@example.com}}"

# Next.js loads web/.env.local itself. Do not override SMTP settings from
# that file; use Mailpit defaults only when no SMTP settings were supplied.
if [[ -z "${SMTP_HOST:-}" ]] && ! grep -q '^SMTP_HOST=' "$ROOT_DIR/web/.env.local" 2>/dev/null; then
  export SMTP_HOST="127.0.0.1"
fi
if [[ -z "${SMTP_PORT:-}" ]] && ! grep -q '^SMTP_PORT=' "$ROOT_DIR/web/.env.local" 2>/dev/null; then
  export SMTP_PORT="1025"
fi
if [[ -z "${SMTP_FROM:-}" ]] && ! grep -q '^SMTP_FROM=' "$ROOT_DIR/web/.env.local" 2>/dev/null; then
  export SMTP_FROM="depguard <no-reply@depguard.local>"
fi

env_value() {
  awk -F= -v key="$1" '$1 == key { print substr($0, index($0, "=") + 1) }' "$ROOT_DIR/deploy/.env"
}

if [[ -f "$ROOT_DIR/deploy/.env" ]]; then
  export GITHUB_APP_ID="${GITHUB_APP_ID:-$(env_value GITHUB_APP_ID)}"
  export GITHUB_APP_SLUG="${GITHUB_APP_SLUG:-$(env_value GITHUB_APP_SLUG)}"
  export GITHUB_WEBHOOK_SECRET="${GITHUB_WEBHOOK_SECRET:-$(env_value GITHUB_WEBHOOK_SECRET)}"
fi
export GITHUB_APP_PRIVATE_KEY="${GITHUB_APP_PRIVATE_KEY:-$ROOT_DIR/deploy/secrets/github-app.pem}"

if [[ -z "${GITHUB_APP_ID:-}" || -z "${GITHUB_APP_SLUG:-}" || -z "${GITHUB_WEBHOOK_SECRET:-}" ]]; then
  echo "Error: GitHub App values are missing from deploy/.env." >&2
  exit 1
fi
[[ -f "$GITHUB_APP_PRIVATE_KEY" ]] || {
  echo "Error: GitHub private key not found at $GITHUB_APP_PRIVATE_KEY" >&2
  exit 1
}

if command -v pnpm >/dev/null 2>&1; then
  WEB_RUNNER=pnpm
else
  WEB_RUNNER=npm
fi

pids=()

stop_tree() {
  local pid="$1"
  local child

  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    stop_tree "$child"
  done

  kill "$pid" 2>/dev/null || true
}

stop_services() {
  trap - EXIT INT TERM

  if ((${#pids[@]} > 0)); then
    echo
    echo "Stopping development servers..."
    for pid in "${pids[@]}"; do
      stop_tree "$pid"
    done
    wait "${pids[@]}" 2>/dev/null || true
  fi
}

stop_on_signal() {
  stop_services
  exit 130
}

trap stop_services EXIT
trap stop_on_signal INT TERM

echo "Starting API, worker, and web servers..."
echo "Prerequisite: local Postgres is only needed when no external DATABASE_URL is configured."
echo ""

echo "Applying web database migrations..."
if [[ "$WEB_RUNNER" == pnpm ]]; then
  (cd web && pnpm db:migrate)
else
  (cd web && npm run db:migrate)
fi

(exec env HTTP_ADDR=":${DEV_API_PORT}" go run ./cmd/api) &
pids+=("$!")

(exec env WORKER_HEALTH_ADDR=":${DEV_WORKER_HEALTH_PORT}" go run ./cmd/worker) &
pids+=("$!")

(cd web && exec "$WEB_RUNNER" run dev) &
pids+=("$!")

echo "API:    http://localhost:${DEV_API_PORT}"
echo "Worker: http://localhost:${DEV_WORKER_HEALTH_PORT}"
echo "Web:    http://localhost:3000"
echo "Mailpit: http://localhost:8025"
echo "Press Ctrl-C to stop all three servers."

# Bash on macOS does not provide `wait -n`, so poll the child processes and
# stop the stack as soon as one of them exits.
while true; do
  for pid in "${pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      if wait "$pid"; then
        status=0
      else
        status=$?
      fi
      echo "A development server exited with status $status; stopping the others." >&2
      exit "$status"
    fi
  done
  sleep 1
done
