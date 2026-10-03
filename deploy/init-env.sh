#!/bin/sh
# Creates deploy/.env from .env.example: asks for domains/emails and generates
# every secret. Re-running keeps values that are already set.
#   cd deploy && ./init-env.sh
set -eu
cd "$(dirname "$0")"
[ -f .env ] || cp .env.example .env

get() { grep -E "^$1=" .env | head -1 | cut -d= -f2-; }
set_var() { # set_var NAME VALUE (replaces the line, keeps everything else)
  tmp=$(mktemp)
  awk -v k="$1" -v v="$2" 'BEGIN{FS=OFS="="} $1==k{print k"="v; done=1; next} {print} END{if(!done) print k"="v}' .env > "$tmp"
  mv "$tmp" .env
}
ask() { # ask NAME "question" default — only when unset or still the example value
  cur=$(get "$1")
  case "$cur" in ""|*example.com*) ;; *) return ;; esac
  printf '%s [%s]: ' "$2" "$3"; read -r ans
  set_var "$1" "${ans:-$3}"
}

# No domain needed: the dashboard runs on http://<server>/ and the API on :8080.
# Add domains later by setting APP_HOST/API_HOST and switching the URLs to https.
if [ -z "$(get PUBLIC_URL)" ]; then
  guess=$(hostname -I 2>/dev/null | awk '{print $1}')
  printf 'Server public IP or hostname [%s]: ' "${guess:-localhost}"; read -r host
  host=${host:-${guess:-localhost}}
  set_var PUBLIC_URL "http://$host"
  set_var PUBLIC_API_URL "http://$host:8080"
fi
ask SUPERADMIN_EMAILS "Platform admin email(s), comma-separated" "you@example.com"

for k in POSTGRES_PASSWORD DEPGUARD_APP_PASSWORD DEPGUARD_QUERY_PASSWORD DEPGUARD_WEB_PASSWORD SERVICE_JWT_SECRET BETTER_AUTH_SECRET; do
  [ -n "$(get "$k")" ] || set_var "$k" "$(openssl rand -hex 32)"
done
chmod 600 .env
echo "deploy/.env ready. Still to fill: GITHUB_* (run: go run ./cmd/ghapp-setup ...) and SMTP_*."
