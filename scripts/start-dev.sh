#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is required but was not found in PATH." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Error: Docker is not running. Start Docker Desktop and try again." >&2
  exit 1
fi

echo "Starting local Postgres and Mailpit..."
make dev-db DEV_DB_PORT=5432

echo "Starting depguard development services..."
exec env DEV_DB_PORT=5432 "$ROOT_DIR/scripts/run-dev.sh"
