# Testing

| Layer | Command | Needs |
|---|---|---|
| Go unit + integration (RLS, engine with fake GitHub, API, query guards, MCP) | `go test ./...` | Docker (testcontainers) |
| Web lint/types | `cd web && pnpm lint && pnpm typecheck` | — |
| Web UI smoke (mock API) | `cd web && pnpm test:e2e` | — |
| Real stack (web + api + worker + Postgres + Mailpit + live feeds) | `node test/e2e/real-stack.mjs` | stack below |

## Risk analysis tests (attack paths, suspicious, licenses, report)
Run only these: `go test ./internal/httpapi/... ./internal/render/... ./cmd/depguard/`.

| Test | Covers |
|---|---|
| `internal/render` `TestRiskGolden` | PR comment with "Introduced via", Dependency column, Suspicious/License sections (`testdata/comment_risk.md`); `render.Full` md/html goldens (`testdata/full.md`, `full.html`); json verdict/counts; HTML escaping. Regenerate with `go test ./internal/render -update`. |
| `internal/render` `TestPathsAndScore` | Path score formula table, path ranking, fix advice, `name@version` parsing. |
| `internal/httpapi` `TestAttackPaths` | `/projects/{id}/versions/{vid}/paths` (BFS chains, nodes/edges subgraph, fixed_in from OSV ranges, EPSS/KEV via CVE alias, target/advisory filters), `/scans/{id}/paths`, `/vulnerabilities/{id}/paths`, tenant isolation of every new endpoint. |
| `internal/httpapi` `TestRiskLists` | `direct=` filters and columns, violation `severity/blocking/details` + filters, dashboard KPIs, `/scans/{id}` package graph fields and `findings`. |
| `internal/httpapi` `TestReport` | `/scans/{id}/report?format=md\|json\|html` sections, headers, machine `/v1/scans/{id}/report`. |
| `internal/httpapi` `TestProjectSettingsAndLicenses` | `/projects/{id}/settings` GET/PUT (RBAC, validation, override/clear), `/licenses` findings + distribution. |
| `internal/httpapi` `TestPolicyRiskPresets` | `presets.suspicious` / `presets.license` defaults, round trip, validation. |
| `internal/httpapi` `TestUploadProjectSettings` | `project_license` / `usage_model` multipart fields stored on the project. |
| `cmd/depguard` `TestFindLockfiles`, `TestScanCommand` | Manifest + root LICENSE upload (lockfiles first), `--format report`, `--report-out`, `--project-license`, `--usage-model`. |
| `web/e2e/smoke.spec.ts` | Attack Paths graph + Licenses tab, dependency column/filter, report download menu, Package Analysis suspicious findings, violation filters, dashboard KPIs, policy presets (mock API). |

Seed data for the API tests is tenant `tr` in `internal/httpapi/risk_test.go`: an MIT project with
`app → express → body-parser → qs` (KEV advisory), a typosquat `lodahs`, a deprecated dev dependency
`request` and a GPL-3.0 dependency.

## Real-stack run
1. `make dev-db` (Postgres + Mailpit), then run `go run ./cmd/api` and `go run ./cmd/worker` with the
   `DEV_ENV` variables from the Makefile. Wait until **Admin → Ops health** (or `sync_state`) shows all
   OSV sources synced (npm takes ~3 min).
2. Web: `cd web && pnpm db:migrate && pnpm build && pnpm start -p 13000` with `SUPERADMIN_EMAILS=admin@example.com`,
   `SMTP_HOST=127.0.0.1 SMTP_PORT=1025`, `API_URL`, `SERVICE_JWT_SECRET` (same as api), `BETTER_AUTH_*`.
3. `go build -o /tmp/depguard ./cmd/depguard && DEPGUARD_BIN=/tmp/depguard E2E_API_URL=http://127.0.0.1:8080 node test/e2e/real-stack.mjs`

The run signs in by magic link as super-admin, creates a tenant, accepts the owner invitation, creates an
API key in the UI, uploads scans through the CLI (`test/e2e/fixtures/e2e-app`: a real vulnerable lodash
and an OSV `MAL-` package), checks in an endpoint agent, and visits every page (screenshots in
`$E2E_WORKDIR/shots`).

## Accuracy cross-check
Matching against the local OSV mirror equals osv-scanner on the same lockfile (verified on an 898-component
npm project: 33 vulnerable packages, 130 advisories, identical sets):
`go run github.com/google/osv-scanner/v2/cmd/osv-scanner scan source --format json -L package-lock.json`.

## GitHub App end to end
Requires a real GitHub App (see DEPLOY.md §3) and a public webhook URL (e.g. `smee.io` or a tunnel to the
api). Open a PR adding a known-malicious and a vulnerable package: expect a failing check run and exactly
one PR comment that is edited (not duplicated) on the next push.
