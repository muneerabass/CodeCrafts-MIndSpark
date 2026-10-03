# Deploying depguard (single host, Docker Compose)

## 1. Server
- A Linux VM with Docker Engine + Compose plugin. 4 vCPU / 8 GB RAM / 80 GB disk is enough to start
  (the OSV mirror is a few GB; scans are CPU-bound). Open ports 80 and 8080 (and 443 once you add domains).
- **No domain needed to start**: the dashboard runs at `http://<server-ip>/` and the API at
  `http://<server-ip>:8080/`.
- **Adding domains later**: point two DNS A records (e.g. `app.example.com`, `api.example.com`) at the VM,
  set `APP_HOST`/`API_HOST` in `deploy/.env`, change `PUBLIC_URL`/`PUBLIC_API_URL` to the `https://`
  domain URLs, update the GitHub App's webhook/callback URLs, and restart — Caddy obtains certificates
  automatically.

## 2. Configure
```sh
git clone <your repo> depguard && cd depguard/deploy
./init-env.sh        # asks for the server IP + your admin email, generates all secrets
# then add SMTP_* (email provider) and GITHUB_* (step 3) to deploy/.env
```

## 3. Create the GitHub App (one time)
From any machine with Go and a browser:
```sh
go run ./cmd/ghapp-setup -app-url http://<server-ip> -api-url http://<server-ip>:8080 [-org your-org]
```
Open the printed local URL, confirm on GitHub, then copy the printed `GITHUB_*` lines into
`deploy/.env` and the key file to `deploy/secrets/github-app.pem` (mode 600). The app requests:
Contents read, Pull requests read, Checks write, Issues write (PR comments), Metadata read; events
pull_request, push, check_run (installation events are always delivered). The same app's client
id/secret are used for "Sign in with GitHub" (callback `<PUBLIC_URL>/api/auth/callback/github`).

Optional Google login: create an OAuth client with redirect `<PUBLIC_URL>/api/auth/callback/google`.

## 4. Start
```sh
docker compose --env-file .env up -d --build
docker compose --env-file .env logs -f api worker
```
On first start the api applies database migrations, then the worker begins mirroring OSV, KEV and
EPSS. The initial OSV bootstrap takes a while (npm is the largest ecosystem); progress is visible in
**Admin → Ops health**. To bootstrap faster/explicitly:
`docker compose exec worker depguard-feeds sync --once`.

## 5. First login and first tenant
1. Sign in at `PUBLIC_URL` with an email listed in `SUPERADMIN_EMAILS` (platform admin).
2. **Admin → Tenants → Create tenant**: name + owner email. The owner receives an invitation email.
3. Install the GitHub App on the customer's org (Setup → Integrations → "Add another organization").
   New installations appear under **Admin → Pending installations**; link them to the tenant. Until
   linked, the app ignores that org's pull requests entirely.
4. Open a pull request that changes a lockfile — a check run and a single PR comment appear.

## 6. Operations
- **Backups**: the `backup` service writes nightly `pg_dump` files for both databases into the
  `backups` volume (kept `BACKUP_KEEP_DAYS`). Copy them off-site, e.g. a cron job on the host:
  `docker run --rm -v depguard_backups:/b:ro rclone/rclone sync /b remote:depguard-backups`.
- **Restore drill** (do this before going live):
  ```sh
  docker compose stop api worker web
  docker compose exec -T postgres pg_restore -U depguard -d depguard --clean --if-exists < depguard-<ts>.dump
  docker compose exec -T postgres pg_restore -U depguard -d depguard_web --clean --if-exists < depguard_web-<ts>.dump
  docker compose start api worker web
  ```
- **Upgrades**: `git pull && docker compose --env-file .env up -d --build` (migrations run automatically).
- **Health**: `<PUBLIC_API_URL>/healthz`; Admin → Ops health shows feed freshness, failed jobs and
  webhook deliveries (with redeliver). River's job UI is under Admin → Jobs.
- **Secrets rotation**: rotate `GITHUB_WEBHOOK_SECRET` in the GitHub App settings and `.env` together;
  rotating `SERVICE_JWT_SECRET` or `BETTER_AUTH_SECRET` signs everyone out.

## 7. Security notes
- Repository code is never executed: only lockfiles/manifests (and, for AI-BOM, changed source files)
  are fetched by SHA and parsed. Size and count limits apply.
- Tenant isolation is enforced by Postgres row-level security on every tenant table; the Query page
  runs as a separate read-only role with a 10 s timeout and 1,000-row cap.
- `/api/v1` (web→api, service JWT) and `/admin` are not exposed on the public API host.
- guarddog runs inside the worker container (non-root, read-only rootfs, no capabilities) and applies
  its own Landlock sandbox.
