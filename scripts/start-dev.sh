#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if grep -Eq '^[[:space:]]*DATABASE_(URL|OWNER_URL|QUERY_URL|URL_WEB)[[:space:]]*=.*supabase' "$ROOT_DIR/web/.env.local" 2>/dev/null; then
  echo "Using configured Supabase PostgreSQL; skipping local Postgres."
else
  if ! command -v docker >/dev/null 2>&1; then
    echo "Error: Docker is required for local Postgres but was not found in PATH." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is not running. Start Docker Desktop and try again." >&2
    exit 1
  fi
  echo "Starting local Postgres and Mailpit..."
  make dev-db DEV_DB_PORT=5432
fi

echo "Starting depguard development services..."
exec env \
  DEV_DB_PORT=5432 \
  PUBLIC_URL=http://localhost:3000 \
  PUBLIC_API_URL=http://localhost:8081 \
  API_URL=http://localhost:8081 \
  "$ROOT_DIR/scripts/run-dev.sh"
