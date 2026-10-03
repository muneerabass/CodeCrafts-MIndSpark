#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/web/.env.local"

mkdir -p "$(dirname -- "$ENV_FILE")"
touch "$ENV_FILE"

read -r -p "SMTP host (for example, smtp.gmail.com): " SMTP_HOST
read -r -p "SMTP port [587]: " SMTP_PORT
SMTP_PORT="${SMTP_PORT:-587}"
read -r -p "SMTP username/email: " SMTP_USER
read -r -s -p "SMTP password or app password: " SMTP_PASS
printf '\n'
read -r -p "From address [depguard <$SMTP_USER>]: " SMTP_FROM
SMTP_FROM="${SMTP_FROM:-depguard <$SMTP_USER>}"

quote_env() {
  local value="$1"
  value=${value//\'/\'\\\'\'}
  printf "'%s'" "$value"
}

tmp_file="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
trap 'rm -f "$tmp_file"' EXIT

grep -Ev '^(SMTP_HOST|SMTP_PORT|SMTP_USER|SMTP_PASS|SMTP_FROM)=' "$ENV_FILE" >"$tmp_file" || true
{
  printf 'SMTP_HOST=%s\n' "$(quote_env "$SMTP_HOST")"
  printf 'SMTP_PORT=%s\n' "$(quote_env "$SMTP_PORT")"
  printf 'SMTP_USER=%s\n' "$(quote_env "$SMTP_USER")"
  printf 'SMTP_PASS=%s\n' "$(quote_env "$SMTP_PASS")"
  printf 'SMTP_FROM=%s\n' "$(quote_env "$SMTP_FROM")"
} >>"$tmp_file"

chmod 600 "$tmp_file"
mv "$tmp_file" "$ENV_FILE"
trap - EXIT

echo "SMTP settings saved to web/.env.local."
echo "Restart the development server, then check invitation emails at http://localhost:8025 when using Mailpit."
