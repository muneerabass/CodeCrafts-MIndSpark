#!/usr/bin/env bash
# Native (no Docker) install/upgrade of depguard on Amazon Linux 2023 / RHEL-like hosts.
#
#   sudo ./deploy/native/install.sh            # from the source checkout on the server
#
# Inputs:  /etc/depguard/deploy.conf (hosts, emails, GitHub App, Supabase, SMTP — see deploy.conf.example)
#          /etc/depguard/github-app.pem
# Creates: PostgreSQL 17 + roles/databases, system users depguard/caddy, /opt/depguard (binaries, web),
#          /etc/depguard/{secrets,depguard,web,caddy}.env, systemd units, nightly backups.
# Idempotent: generated passwords/secrets are kept on re-runs.
set -Eeuo pipefail

SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
CONF=/etc/depguard/deploy.conf
CADDY_VERSION=2.10.2
GUARDDOG_VERSION=3.2.0

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run with sudo"
[[ -f $CONF ]] || die "missing $CONF (copy deploy/native/deploy.conf.example)"
# shellcheck disable=SC1090
. "$CONF"
for v in APP_HOST API_HOST ACME_EMAIL SUPERADMIN_EMAILS GITHUB_APP_ID GITHUB_APP_SLUG GITHUB_WEBHOOK_SECRET \
         NEXT_PUBLIC_SUPABASE_URL NEXT_PUBLIC_SUPABASE_ANON_KEY SUPABASE_SERVICE_ROLE_KEY; do
  [[ -n ${!v:-} ]] || die "$v is empty in $CONF"
done
# Application data lives in the local PostgreSQL this script sets up. Refuse to
# proceed if deploy.conf tries to override an application DATABASE_URL with a
# Supabase DSN — Supabase is only used for Auth.
for v in DATABASE_URL DATABASE_OWNER_URL DATABASE_QUERY_URL DATABASE_URL_WEB; do
  if [[ "${!v:-}" == *supabase.co* || "${!v:-}" == *pooler.supabase.com* ]]; then
    die "$v in $CONF points at Supabase. Remove it: application data must live in local PostgreSQL (Supabase is Auth only)."
  fi
done
[[ -f /etc/depguard/github-app.pem ]] || die "missing /etc/depguard/github-app.pem"

log "Packages"
dnf -y -q install postgresql17-server postgresql17 nodejs22 nodejs22-npm python3.12 python3.12-pip golang git gcc gcc-c++ make tar >/dev/null
command -v node >/dev/null || ln -sf "$(ls /usr/bin/node-22 2>/dev/null || ls /usr/bin/node*22* | head -1)" /usr/bin/node
command -v pnpm >/dev/null || npm install -g --silent pnpm@11
id depguard &>/dev/null || useradd --system --home /var/lib/depguard --shell /sbin/nologin depguard
id caddy &>/dev/null || useradd --system --home /var/lib/caddy --shell /sbin/nologin caddy
install -d -o depguard -g depguard -m 750 /var/lib/depguard
install -d -o caddy -g caddy -m 750 /var/lib/caddy
install -d -o postgres -g postgres -m 750 /var/backups/depguard
install -d -m 755 /opt/depguard /opt/depguard/bin /etc/caddy /var/cache/depguard

log "Secrets"
SECRETS=/etc/depguard/secrets.env
touch "$SECRETS"; chmod 600 "$SECRETS"
for k in OWNER_DB_PASSWORD APP_DB_PASSWORD QUERY_DB_PASSWORD WEB_DB_PASSWORD SERVICE_JWT_SECRET DEPGUARD_SECRET_KEY; do
  grep -q "^$k=" "$SECRETS" || echo "$k=$(openssl rand -hex 32)" >> "$SECRETS"
done
# shellcheck disable=SC1090
. "$SECRETS"

log "PostgreSQL 17"
if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]]; then
  postgresql-setup --initdb >/dev/null
  # Local password auth over TCP; peer auth for the postgres OS user.
  cat > /var/lib/pgsql/data/pg_hba.conf <<'HBA'
local   all   postgres                peer
local   all   all                     scram-sha-256
host    all   all   127.0.0.1/32      scram-sha-256
host    all   all   ::1/128           scram-sha-256
HBA
  sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost'/" /var/lib/pgsql/data/postgresql.conf
fi
systemctl enable --now postgresql >/dev/null
sudo -u postgres psql -v ON_ERROR_STOP=1 -q <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='depguard') THEN CREATE ROLE depguard LOGIN SUPERUSER; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='depguard_app') THEN CREATE ROLE depguard_app LOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='depguard_query') THEN CREATE ROLE depguard_query LOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='depguard_web') THEN CREATE ROLE depguard_web LOGIN; END IF;
END \$\$;
ALTER ROLE depguard PASSWORD '$OWNER_DB_PASSWORD';
ALTER ROLE depguard_app PASSWORD '$APP_DB_PASSWORD';
ALTER ROLE depguard_query PASSWORD '$QUERY_DB_PASSWORD';
ALTER ROLE depguard_web PASSWORD '$WEB_DB_PASSWORD';
ALTER ROLE depguard_query SET statement_timeout = '10s';
SQL
for db in depguard:depguard depguard_web:depguard_web; do
  name=${db%%:*}; owner=${db##*:}
  sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$name'" | grep -q 1 \
    || sudo -u postgres createdb -O "$owner" "$name"
done
sudo -u postgres psql -q -d depguard -c "GRANT CONNECT ON DATABASE depguard TO depguard_app, depguard_query; GRANT USAGE ON SCHEMA public TO depguard_app, depguard_query;"

log "Environment files"
DB=127.0.0.1:5432
cat > /etc/depguard/depguard.env <<ENV
DATABASE_URL=postgres://depguard_app:$APP_DB_PASSWORD@$DB/depguard?sslmode=disable
DATABASE_OWNER_URL=postgres://depguard:$OWNER_DB_PASSWORD@$DB/depguard?sslmode=disable
DATABASE_QUERY_URL=postgres://depguard_query:$QUERY_DB_PASSWORD@$DB/depguard?sslmode=disable
SERVICE_JWT_SECRET=$SERVICE_JWT_SECRET
PUBLIC_URL=https://$APP_HOST
PUBLIC_API_URL=https://$API_HOST
TENANT_DOMAIN_SUFFIX=${TENANT_DOMAIN_SUFFIX:-$APP_HOST}
GITHUB_APP_ID=$GITHUB_APP_ID
GITHUB_APP_SLUG=$GITHUB_APP_SLUG
GITHUB_WEBHOOK_SECRET=$GITHUB_WEBHOOK_SECRET
GITHUB_APP_PRIVATE_KEY=/etc/depguard/github-app.pem
CHECK_RUN_NAME=${CHECK_RUN_NAME:-depguard: Supply Chain Security}
GUARDDOG_BIN=/opt/depguard/guarddog/bin/guarddog
DEPGUARD_DATA_DIR=/var/lib/depguard
LOG_LEVEL=info
AI_REVIEW_CONFIGURED=$([ -n "${GEMINI_API_KEY:-}${AWS_BEARER_TOKEN_BEDROCK:-}" ] && echo 1 || echo 0)
DEPGUARD_AI_MODELS=${DEPGUARD_AI_MODELS:-}
DEPGUARD_GEMINI_MODELS=${DEPGUARD_GEMINI_MODELS:-}
# Encrypts team secrets stored in the database (Slack webhook, Jira token).
DEPGUARD_SECRET_KEY=$DEPGUARD_SECRET_KEY
# Alert and digest emails (same mailbox as the web app's invitations).
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-587}
SMTP_USER=${SMTP_USER:-}
SMTP_PASS=${SMTP_PASS:-}
SMTP_FROM="${SMTP_FROM:-depguard <no-reply@$APP_HOST>}"
ENV
# AI keys (PR review in the worker, "Ask depguard" in the API). Gemini wins when set.
cat > /etc/depguard/ai.env <<ENV
GEMINI_API_KEY=${GEMINI_API_KEY:-}
AWS_BEARER_TOKEN_BEDROCK=${AWS_BEARER_TOKEN_BEDROCK:-}
ENV
chown root:depguard /etc/depguard/ai.env; chmod 640 /etc/depguard/ai.env
cat > /etc/depguard/web.env <<ENV
DATABASE_URL_WEB=postgres://depguard_web:$WEB_DB_PASSWORD@$DB/depguard_web?sslmode=disable
API_URL=http://127.0.0.1:8080
PUBLIC_URL=https://$APP_HOST
PUBLIC_API_URL=https://$API_HOST
SERVICE_JWT_SECRET=$SERVICE_JWT_SECRET
TENANT_DOMAIN_SUFFIX=${TENANT_DOMAIN_SUFFIX:-$APP_HOST}
SUPERADMIN_EMAILS=$SUPERADMIN_EMAILS
NEXT_PUBLIC_SUPABASE_URL=$NEXT_PUBLIC_SUPABASE_URL
NEXT_PUBLIC_SUPABASE_ANON_KEY=$NEXT_PUBLIC_SUPABASE_ANON_KEY
SUPABASE_SERVICE_ROLE_KEY=$SUPABASE_SERVICE_ROLE_KEY
NEXT_PUBLIC_SUPABASE_GITHUB_ENABLED=${NEXT_PUBLIC_SUPABASE_GITHUB_ENABLED:-1}
NEXT_PUBLIC_SUPABASE_GOOGLE_ENABLED=${NEXT_PUBLIC_SUPABASE_GOOGLE_ENABLED:-0}
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-587}
SMTP_USER=${SMTP_USER:-}
SMTP_PASS=${SMTP_PASS:-}
SMTP_FROM="${SMTP_FROM:-depguard <no-reply@$APP_HOST>}"
ENV
printf 'APP_HOST=%s\nAPI_HOST=%s\nACME_EMAIL=%s\n' "$APP_HOST" "$API_HOST" "$ACME_EMAIL" > /etc/depguard/caddy.env
chown root:depguard /etc/depguard/depguard.env /etc/depguard/web.env /etc/depguard/github-app.pem
chmod 640 /etc/depguard/depguard.env /etc/depguard/web.env /etc/depguard/github-app.pem
chown root:caddy /etc/depguard/caddy.env; chmod 640 /etc/depguard/caddy.env
chmod 750 /etc/depguard; chown root:depguard /etc/depguard
setfacl -m u:caddy:x /etc/depguard 2>/dev/null || chmod 751 /etc/depguard

log "Build Go binaries (cgo)"
# Amazon Linux's Go package sets GOSUMDB=off; re-enable checksum verification (needed to fetch
# the go1.27 toolchain and to verify every module download).
export GOSUMDB=sum.golang.org GOPROXY=https://proxy.golang.org,direct
export GOTOOLCHAIN=auto GOFLAGS=-mod=mod GOPATH=/var/cache/depguard/go GOCACHE=/var/cache/depguard/go/build
mkdir -p "$GOPATH"
(cd "$SRC" && CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o /opt/depguard/bin/ \
   ./cmd/api ./cmd/worker ./cmd/depguard ./cmd/depguard-feeds)

log "Build CLI downloads (install.sh, npm package, PyPI wheels)"
(cd "$SRC" && VERSION="0.1.$(date -u +%Y%m%d%H%M)" DEPGUARD_APP_URL="https://$APP_HOST" DEPGUARD_API_URL="https://$API_HOST" \
   sh packaging/build.sh >/dev/null)
rm -rf /opt/depguard/downloads.new && cp -a "$SRC/dist/downloads" /opt/depguard/downloads.new
chmod -R a+rX /opt/depguard/downloads.new
rm -rf /opt/depguard/downloads && mv /opt/depguard/downloads.new /opt/depguard/downloads

log "Build web app"
WEB_BUILD="$SRC/web"
(cd "$WEB_BUILD" && pnpm install --frozen-lockfile --silent --store-dir /var/cache/depguard/pnpm \
  && set -a && . /etc/depguard/web.env && set +a \
  && NEXT_TELEMETRY_DISABLED=1 pnpm build >/dev/null \
  && pnpm exec drizzle-kit migrate)
rm -rf /opt/depguard/web.new && mkdir -p /opt/depguard/web.new
cp -a "$WEB_BUILD/.next/standalone/." /opt/depguard/web.new/
mkdir -p /opt/depguard/web.new/.next && cp -a "$WEB_BUILD/.next/static" /opt/depguard/web.new/.next/static
cp -a "$WEB_BUILD/public" /opt/depguard/web.new/public
rm -rf /opt/depguard/web.old; [[ -d /opt/depguard/web ]] && mv /opt/depguard/web /opt/depguard/web.old
mv /opt/depguard/web.new /opt/depguard/web
chown -R root:root /opt/depguard

log "guarddog $GUARDDOG_VERSION"
[[ -x /opt/depguard/guarddog/bin/guarddog ]] || {
  python3.12 -m venv /opt/depguard/guarddog
  /opt/depguard/guarddog/bin/pip install -q "guarddog==$GUARDDOG_VERSION"
}
# guarddog refreshes its top-package lists in place; give the service user write access there.
chown -R depguard "$(/opt/depguard/guarddog/bin/python -c 'import guarddog,os;print(os.path.dirname(guarddog.__file__))')/analyzer/metadata/resources"

log "Caddy $CADDY_VERSION"
if ! /usr/local/bin/caddy version 2>/dev/null | grep -q "v$CADDY_VERSION"; then
  curl -fsSL "https://github.com/caddyserver/caddy/releases/download/v$CADDY_VERSION/caddy_${CADDY_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin caddy
fi
install -m 644 "$SRC/deploy/native/Caddyfile" /etc/caddy/Caddyfile

log "systemd units"
install -m 644 "$SRC"/deploy/native/systemd/*.service "$SRC"/deploy/native/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now depguard-backup.timer >/dev/null
systemctl enable depguard-api depguard-worker depguard-web caddy >/dev/null
systemctl restart depguard-api
for i in $(seq 1 60); do curl -fs http://127.0.0.1:8080/readyz >/dev/null && break; sleep 2; done
systemctl restart depguard-worker depguard-web caddy

log "Status"
for s in postgresql depguard-api depguard-worker depguard-web caddy; do
  printf '%-18s %s\n' "$s" "$(systemctl is-active $s)"
done
echo "API ready:    $(curl -fs http://127.0.0.1:8080/readyz || echo no)"
echo "Worker:       $(curl -fs http://127.0.0.1:8081/healthz || echo no)"
echo "Web:          $(curl -fs -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/sign-in || echo no)"
echo "Public URLs:  https://$APP_HOST  (web)   https://$API_HOST  (API)"
