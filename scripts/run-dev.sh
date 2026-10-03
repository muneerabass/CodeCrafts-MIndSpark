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
export DATABASE_URL="${DATABASE_URL:-postgres://depguard_app:dev@localhost:${DEV_DB_PORT}/depguard?sslmode=disable}"
export DATABASE_OWNER_URL="${DATABASE_OWNER_URL:-postgres://depguard:dev@localhost:${DEV_DB_PORT}/depguard?sslmode=disable}"
export DATABASE_QUERY_URL="${DATABASE_QUERY_URL:-postgres://depguard_query:dev@localhost:${DEV_DB_PORT}/depguard?sslmode=disable}"
export DATABASE_URL_WEB="${DATABASE_URL_WEB:-postgres://depguard_web:dev@localhost:${DEV_DB_PORT}/depguard_web?sslmode=disable}"
export SERVICE_JWT_SECRET="${SERVICE_JWT_SECRET:-dev-only-service-jwt-secret-0123456789abcdef}"
export BETTER_AUTH_SECRET="${BETTER_AUTH_SECRET:-dev-only-better-auth-secret-0123456789abcdef}"
export PUBLIC_URL="${PUBLIC_URL:-http://localhost:3000}"
export PUBLIC_API_URL="${PUBLIC_API_URL:-http://localhost:${DEV_API_PORT}}"
export API_URL="${API_URL:-http://localhost:${DEV_API_PORT}}"
export BETTER_AUTH_URL="${BETTER_AUTH_URL:-http://localhost:3000}"
export TENANT_DOMAIN_SUFFIX="${TENANT_DOMAIN_SUFFIX:-localhost}"
export SUPERADMIN_EMAILS="${SUPERADMIN_EMAILS:-admin@example.com}"
export SMTP_HOST="${SMTP_HOST:-127.0.0.1}"
export SMTP_PORT="${SMTP_PORT:-1025}"
export SMTP_FROM="${SMTP_FROM:-depguard <no-reply@depguard.local>}"

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

stop_services() {
  trap - EXIT INT TERM

  if ((${#pids[@]} > 0)); then
    echo
    echo "Stopping development servers..."
    kill "${pids[@]}" 2>/dev/null || true
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
echo "Prerequisite: run 'make dev-db' once if Postgres and Mailpit are not running."
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
