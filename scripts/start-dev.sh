#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Application data lives in a local PostgreSQL (Supabase is only used for Auth).
# Fail fast if any application DB URL in web/.env.local still points at Supabase.
if grep -Eq '^[[:space:]]*DATABASE_(URL|OWNER_URL|QUERY_URL|URL_WEB)[[:space:]]*=.*(pooler\.supabase\.com|supabase\.co)' "$ROOT_DIR/web/.env.local" 2>/dev/null; then
  echo "Error: web/.env.local still has a Supabase DATABASE_URL*. Point DATABASE_URL," >&2
  echo "       DATABASE_OWNER_URL, DATABASE_QUERY_URL and DATABASE_URL_WEB at local PostgreSQL." >&2
  echo "       Supabase is now used only for Auth (NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY," >&2
  echo "       SUPABASE_SERVICE_ROLE_KEY)." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is required for local Postgres but was not found in PATH." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Error: Docker is not running. Start Docker Desktop and try again." >&2
  exit 1
fi
echo "Starting local Postgres and Mailpit..."
# Port 55432 avoids clashing with another Postgres on 5432 (quick-commerce, system pg, etc).
# run-dev.sh defaults to the same port, and web/.env.local must match.
make dev-db DEV_DB_PORT=55432

echo "Starting depguard development services..."
exec env \
  DEV_DB_PORT=55432 \
  PUBLIC_URL=http://localhost:3000 \
  PUBLIC_API_URL=http://localhost:8081 \
  API_URL=http://localhost:8081 \
  "$ROOT_DIR/scripts/run-dev.sh"
