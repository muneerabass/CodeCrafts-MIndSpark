# depguard — internal contracts

Source of truth shared by all workstreams. Change it only with care: other packages depend on it.
Full plan: `/home/manas/.claude/plans/snug-nibbling-cocoa.md`.

## Repo layout
```
depguard/
  go.mod                 module github.com/depguard/depguard (Go 1.27). DO NOT edit deps without coordination.
  migrations/            goose SQL (00001_init.sql = full domain schema + RLS + query views), embed.go
  internal/db            Open, Migrate, WithTenantTx, WithSystemTx            (exists)
  internal/ids           ULID                                                   (exists)
  internal/jobs          River job arg types                                    (exists)
  internal/scan          vet-based parse + CEL policy                           (exists: Parse, Policy, DefaultRules)
  internal/feeds         OSV / KEV / EPSS sync + River periodic jobs            (workstream A)
  internal/enrich        OSV-backed vet enricher + deps.dev/Scorecard cache     (workstream A)
  internal/engine        scan pipeline: fetch → parse → diff → enrich → policy → persist  (workstream B)
  internal/ghapp         GitHub App: webhooks, installs, check runs, sticky comment       (workstream B)
  internal/render        PR comment + check run markdown                        (workstream B)
  internal/httpapi       REST API for web, ingest, admin; mounts ghapp + MCP    (workstream C)
  internal/mcpserver     MCP tools over our data                                (workstream C)
  internal/auth          service-JWT + API key verification                     (workstream C)
  cmd/api                HTTP server (C)      cmd/worker  River worker (B)
  cmd/depguard           CLI: `depguard scan` (upload lockfiles), `depguard agent` (endpoint agent) (C)
  web/                   Next.js app (workstream D)
  deploy/                compose, Caddyfile, Dockerfiles (workstream E)
```

## Database
- Runtime role `depguard_app` (RLS enforced). Owner role only for migrations (`db.Migrate`).
- **All tenant-table access goes through `db.WithTenantTx(ctx, pool, tenantID, fn)`.** Global tables
  (advisory*, affected, cve_score, package_meta, scorecard, sync_state, gh_installations,
  gh_repositories, webhook_deliveries) via `db.WithSystemTx`.
- `tenant_id` = Better Auth `organization.id`. IDs are ULIDs (`ids.New()`).
- Ecosystem strings in `components.ecosystem` are vet's `models.Ecosystem*` values (npm, PyPI, Go, Maven, …).

## Go package APIs (stable signatures)
```go
// internal/enrich (A)
type Enricher struct{ /* pool, http clients, caches */ }
func New(pool *pgxpool.Pool, opts Options) *Enricher
// Enrich fills pkg.Insights (gen/insightapi.PackageVersionInsight) for every package:
// Vulnerabilities (Id, Aliases, Summary, Severities[{Type:CVSS_V3, Risk, Score}]),
// Licenses (SPDX), Projects (github repo stars/forks), Scorecard. Risk is derived from CVSS
// so vet's CEL buckets vulns.critical/high/medium/low work. MAL- advisories included (risk CRITICAL).
func (e *Enricher) Enrich(ctx context.Context, pkgs []*models.Package) error

// internal/feeds (A)
func PeriodicJobs() []*river.PeriodicJob          // OSV 15m, KEV 1h, EPSS 24h
func AddWorkers(w *river.Workers, pool *pgxpool.Pool)
func Status(ctx, pool) ([]SourceStatus, error)    // for admin ops health

// internal/engine (B)
func AddWorkers(w *river.Workers, deps Deps)       // ScanPullRequest, ScanRepository, ScanUpload, GuarddogAnalyze, SyncInstallation

// internal/ghapp (B)
func NewWebhookHandler(deps Deps) http.Handler     // mounted by C at POST /github/webhook
func InstallURL(cfg Config) string
func Redeliver(ctx, cfg, deliveryID string) error  // used by admin endpoint
```

## Service auth (web → api)
- Web server signs HS256 JWT with `SERVICE_JWT_SECRET`, exp ≤ 60 s, header `Authorization: Bearer <jwt>`.
- Claims: `tid` (tenant/organization id, may be empty for super-admin routes), `uid`, `role`
  (`owner|admin|member`), `sa` (bool, platform super-admin), `email`, `name`.
- Permissions: member = read-only; admin/owner = write settings, keys, exclusions, policy, scans, verify;
  only owner = (members are managed in web/Better Auth). `/api/v1/admin/*` requires `sa=true`.

## API keys (CLI, CI, agent, MCP)
- Format `dg_<32 random base62>`; stored as sha256 in `api_keys.key_hash`; `prefix` = first 12 chars.
- Header `Authorization: Bearer dg_...`. Tenant derived from the key. Created/listed/revoked via `/api/v1/api-keys`.

## REST API — `/api/v1/*` (web, service JWT)
Conventions: JSON; list endpoints take `page` (1-based), `page_size` (10|20|50), return
`{"items":[...],"total":N}`; dates RFC3339; filters as query params; `from`/`to` RFC3339 date range;
booleans `has_vulns=true`, `has_violations=true`. Errors `{"error":"msg"}` with 4xx/5xx.

| Method & path | Response / body |
|---|---|
| GET `/dashboard?range=7d\|30d\|90d` | `{projects, components, suspicious, malicious, violations, vulnerabilities, violations_over_time:[{date,count}], violations_by_check:[{check,count}], vulns_over_time:[{date,critical,high,medium,low}], top_projects:[{id,name,vulns}]}` |
| GET `/projects?name=&source=&from=&to=&has_vulns=&has_violations=` | items `{id,name,source,url,versions,components,violations,vulns,created_at}` |
| GET `/projects/{id}` | `{id,name,source,url,created_at,versions:[{id,name,last_scan_at,updated_at}]}` |
| GET `/projects/{id}/versions/{vid}/summary` | `{components,vulns,violations,versions_available,updated_at}` |
| GET `/projects/{id}/versions/{vid}/components?has_vulns=&has_violations=` | items `{id,name,version,type,ecosystem,violations,vulns,created_at,updated_at}` |
| GET `/projects/{id}/versions/{vid}/vulnerabilities` | items `{id,summary,risk,published,modified}` |
| GET `/projects/{id}/versions/{vid}/violations` | items `{id,rule_name,category,summary,component:{id,name,version,ecosystem},created_at}` |
| GET `/projects/{id}/versions/{vid}/scans` | items `{id,trigger,violations,vulns,status,created_at}` |
| GET `/repositories` | items `{id,full_name,default_branch,private,installation_id}` (linked installs only) |
| POST `/scans` body `{repo_id, branch?}` | `{scan_id}` (manual "Scan a repository") |
| GET `/components?name=&version=&ecosystem=&from=&to=&has_vulns=&has_violations=` | items `{id,name,version,ecosystem,type,projects,violations,vulns,updated_at}` |
| GET `/scans?project_id=&version=&trigger=&status=&from=&to=&has_vulns=&has_violations=` | items `{id,project:{id,name},version,trigger,violations,vulns,status,created_at}` |
| GET `/scans/{id}` | `{id,project,version,trigger,status,conclusion,pr_number,head_sha,created_at,finished_at,error,counts:{components,vulns,violations,malicious,suspicious},report_md,packages:[{component:{id,name,version,ecosystem,purl},manifest_path,change,malware,vulnerable,risky_license,vulns:[{id,summary,risk}],violations:[{rule_name,category,summary}]}]}` |
| GET `/package-analyses?project_id=&version=&from=&to=&status=&verified=` | items `{id,component:{id,name,version,ecosystem},project:{id,name},version,status,verified,created_at}` |
| GET `/package-analyses/{id}` | item + `{source,evidence,verified_by,verified_at,scan_id}` |
| POST `/package-analyses/{id}/verify` body `{status:"malicious"\|"clean"}` | item (admin/owner) |
| GET `/vulnerabilities?risk=&id=&from=&to=` | items `{id,summary,risk,affected_components,affected_projects,published,modified}` |
| GET `/vulnerabilities/{id}` | `{id,summary,details,risk,aliases,severity,published,modified,references,epss,kev}` |
| GET `/vulnerabilities/{id}/components` | items `{component:{id,name,version,ecosystem},projects:[{id,name}]}` |
| GET `/policy/violations?rule=&category=&project_id=&version=` | items `{id,rule_name,category,summary,component,project:{id,name},version,scan_id,created_at}` |
| GET/PUT `/policy` | `{presets:{vulnerability:{min_risk:"CRITICAL"\|"HIGH"\|"MEDIUM"\|"LOW"\|"OFF"}, malware:{enabled:bool}, license:{deny:[spdx-prefix...]}, popularity:{enabled:bool,min_stars:int}, maintenance:{enabled:bool,min_scorecard:float}}, custom:[{name,category,summary,expr}]}` |
| POST `/policy/test` body `{expr, ecosystem, name, version}` | `{matched:bool, error?:string}` |
| GET `/endpoints` | items `{id,identifier,endpoint_type,hostname,os,last_sync_at,inventory_count,created_at}` |
| GET `/endpoints/{id}` ; `/endpoints/{id}/inventory` ; `/endpoints/{id}/package-events` ; `/endpoints/{id}/agent-events` | detail / paginated lists |
| POST `/query` body `{sql}` | `{columns:[...], rows:[[...]], truncated:bool, elapsed_ms}` |
| GET `/query/schema` | `{tables:[{name,columns:[{name,type}]}]}` (q_* views) |
| GET/POST `/queries`, DELETE `/queries/{id}` | saved queries `{id,name,sql,created_at}` |
| GET/PUT `/settings` | `{tenant_id,domain,plan,block_mode,scan_draft_prs,suppress_clean_comments}` |
| GET/POST `/api-keys`, DELETE `/api-keys/{id}` | `{id,name,prefix,created_at,last_used_at,expires_at}`; POST body `{name,expires_at?}` returns `+{key}` once |
| GET/POST `/exclusions?ecosystem=&name=&version=&status=active\|expired&expiry_before=`, PUT/DELETE `/exclusions/{id}` | `{id,ecosystem,name,version,reason,status,expires_at,created_at}` |
| GET `/integrations` | `{github:{install_url, installations:[{id,account_login,status,repos}]}}` |
| **Admin (sa=true)** | |
| POST `/admin/tenants` body `{tenant_id,domain}` | provisions `tenant_settings` (called by web after creating the organization) |
| GET `/admin/tenants` | items `{tenant_id,domain,plan,disabled_at,projects,installations}` ; PATCH `/admin/tenants/{id}` `{disabled:bool}` |
| GET `/admin/installations?status=` ; POST `/admin/installations/{id}/link` `{tenant_id}` ; POST `/admin/installations/{id}/unlink` | |
| GET `/admin/feeds` | `[{source,last_ok,last_error,cursor,updated_at}]` |
| GET `/admin/webhooks?status=` ; POST `/admin/webhooks/{delivery_id}/redeliver` | |
| GET `/admin/jobs/failed` | recent failed/discarded River jobs |
| `/admin/river/*` | River UI (proxied by web with super-admin JWT) |

## Public machine endpoints (API key)
| Method & path | Purpose |
|---|---|
| POST `/v1/scans` multipart: `project` (name), `version` (branch), `source` (cli\|gitlab\|bitbucket\|github), `lockfile` (repeatable file parts, filename = repo path) ; `?wait=true` blocks ≤ 120 s | returns `{scan_id, status, conclusion, report_md, url}` |
| GET `/v1/scans/{id}` | same shape |
| POST `/v1/endpoints/checkin` `{identifier,endpoint_type,hostname,os,agent_version}` | upsert endpoint → `{endpoint_id}` |
| POST `/v1/endpoints/{id}/inventory` `{items:[{kind,name,version,scope,config_path,details}]}` | replace current inventory |
| POST `/v1/endpoints/{id}/pmg-events` JSONL body (pmg eventlog lines) | append |
| POST `/v1/endpoints/{id}/agent-events` JSON array of gryph events (event.schema.json) | append (dedupe by id) |
| `/mcp` | MCP (streamable HTTP/SSE) — tools: get_package_vulnerabilities, get_malware_verdict, get_license_info, get_package_scorecard |
| POST `/github/webhook` | GitHub App webhooks |
| GET `/healthz`, `/readyz`, `/metrics` | ops |

### Install guard (see docs/CLI.md)

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/packages/check` | pre-install verdict: packages and/or before/after lockfiles + manifests + repo rules → `{decision, block_mode, checked, packages[]}` |
| GET | `/v1/me` | tenant of the API key and a policy summary (`depguard login`, `init`, `doctor`) |

Migration 00006 adds `malysis_verdict` (SafeDep community malware verdict cache, shared, no RLS).
Policy JSON: `presets.packages[]` = `{ecosystem?, name, versions?, deny?, allow?, reason?, severity?}`.

## Environment variables

`MALYSIS_DISABLED=1` (api) turns off the SafeDep community malware lookups used by install checks.
```
DATABASE_URL            postgres://depguard_app:...@postgres:5432/depguard   (runtime, RLS)
DATABASE_OWNER_URL      postgres://depguard:...@postgres:5432/depguard        (migrations)
DATABASE_QUERY_URL      postgres://depguard_query:...@postgres:5432/depguard  (Query page)
SERVICE_JWT_SECRET      shared by web and api
PUBLIC_URL              https://app.depguard.dev   (web app; links in PR comments)
PUBLIC_API_URL          https://api.depguard.dev   (machine API: CLI, agent, MCP, webhooks)
HTTP_ADDR               api listen address, default :8080
GITHUB_APP_PRIVATE_KEY  PEM contents OR a file path (compose mounts /run/secrets/github_app_key)
TENANT_DOMAIN_SUFFIX    depguard.dev
GITHUB_APP_ID, GITHUB_APP_SLUG, GITHUB_APP_PRIVATE_KEY (PEM or path), GITHUB_WEBHOOK_SECRET
GITHUB_API_URL          default https://api.github.com/
CHECK_RUN_NAME          default "depguard: Supply Chain Security"
GUARDDOG_IMAGE          sandbox image for guarddog
DEPSDEV_DISABLED, SCORECARD_DISABLED   (tests/offline)
LOG_LEVEL
```

## Deployment hooks (deploy/compose.yml)
- `api healthcheck` subcommand: GET http://127.0.0.1$HTTP_ADDR/healthz, exit 0/1 (distroless image has no curl).
- The api runs migrations (db.Migrate with DATABASE_OWNER_URL) + river migrations before serving; worker starts after api is healthy.
- Postgres init (deploy/postgres/init.sh) pre-creates roles depguard_app / depguard_query / depguard_web with passwords and a separate database `depguard_web` for Better Auth.
- Public reverse proxy blocks /api/v1/* and /admin/* on the API host; the web server reaches the api on the internal network (API_URL=http://api:8080).

## Feeds & enrichment (implemented, workstream A)
- `feeds.New(pool, Options)`, `Syncer.SyncAll/SyncOSV/SyncKEV/SyncEPSS/Ingest`; River job kinds `feeds_osv`, `feeds_kev`, `feeds_epss` (arg types in internal/feeds); `feeds.PeriodicJobs()`, `feeds.AddWorkers(w, pool)`, `feeds.Status(ctx, pool)` (JSON = GET /admin/feeds).
- `enrich.New(pool, Options)`, `Enrich(ctx, pkgs)`, then `enrich.Matches(pkg) []enrich.Match{AdvisoryID,Risk,Summary,Aliases,Malware}` → rows for component_vulnerabilities. Env DEPSDEV_DISABLED/SCORECARD_DISABLED map to Options.DisableDepsDev/DisableScorecard (caller's job).
- `affected.ecosystem` / `package_meta.ecosystem` hold OSV ecosystem names ("crates.io", "GitHub Actions"); ranges live in `affected.ranges` (no affected_range table). sync_state sources: `osv:<Ecosystem>`, `kev`, `epss`.
- Test helper: `internal/feeds/feedstest.Postgres(t)` (testcontainers, migrated, app-role pool).

## Engine & GitHub App (implemented, workstream B)
- Insert ScanRepository/ScanUpload jobs with `ghapp.JobOpts` (MaxAttempts 5, unique while in flight).
- Manual ScanRepository: api pre-creates the scan row (placeholder project/version allowed); worker overwrites project_id, project_version_id, head_sha (version = branch).
- `webhook_deliveries.status` also: `processed` (handled without a job). A `failed` delivery is accepted again on redelivery.
- River tables need `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES` + `USAGE ON ALL SEQUENCES` to depguard_app after rivermigrate (see internal/engine/testpg).
- Worker env: WORKER_HEALTH_ADDR (:8081), WORKER_CONCURRENCY, XBOM_DISABLED, GUARDDOG_BIN, GUARDDOG_ALLOW_NO_SANDBOX.
- Binaries need cgo (vet tree-sitter parsers, xbom).

## API deviations (implemented, workstream C)
- POST /api/v1/scans → 202 {scan_id}. POST /v1/scans and GET /v1/scans/{id} → 202 while queued/running, 200 when finished.
- GET /integrations adds top-level `api_url`, `mcp_url` (from PUBLIC_API_URL).
- POST /v1/endpoints/{id}/agent-events accepts a JSON array or JSONL (gryph export); returns {inserted,duplicates}. pmg ingest returns {inserted}.
- /query, /query/schema, /queries: all roles (read-only). Other writes: admin/owner.
- POST /admin/tenants idempotent; 409 when domain belongs to another tenant.
- MAL- advisories count as malware, not vulnerabilities, in counts. "Current" components = project_versions.last_scan_id (fallback: latest successful non-PR scan).
- SERVICE_JWT_SECRET must be ≥ 32 chars. API key rate limit: 10 rps, burst 50. Ingest ≤ 10k items/request.
- migrations/00002 revokes EXECUTE on pg_catalog.set_config from PUBLIC (prevents tenant switching from the Query role); requires the migration owner to be superuser (docker POSTGRES_USER is).

## Risk analysis (attack paths, transitive, suspicious, licenses) — migration 00003
Plan: `/home/manas/.claude/plans/snug-nibbling-cocoa.md`. Shared Go types: `internal/scan/risk.go`
(`scan.Finding`, `scan.Project`, `scan.PackageContext`, `scan.CheckInput`, `scan.Checker`, Severity*/Usage*/Category*).

### Ownership (parallel workstreams — touch only your paths)
| Stream | Owns |
|---|---|
| A graph+engine | `internal/scan/graph.go`, `internal/scan/manifests.go`, `internal/scan/imports.go`, `internal/enrich/graph.go` (+ `FixedIn` in enrich `Match`), all of `internal/engine/` **except** `guarddog.go` |
| B suspicious | `internal/suspicious/**`, `internal/enrich/latest.go`, `internal/engine/guarddog.go`, `internal/scan/presets.go`, `internal/scan/policy.go` |
| C license | `internal/license/**` |
| D surface | `internal/httpapi/**`, `internal/render/**`, `cmd/depguard/**`, `web/**`, `docs/RISK-MODEL.md`, `docs/TESTING.md` |

### Schema (00003)
- `scan_packages`: `direct bool NULL`, `depth int NULL` (1 = direct), `dev bool NULL`, `via text[]` (shortest chain root→pkg, `name@version`, last = the package), `paths jsonb` (≤3 chains, `[["a@1","b@2","pkg@3"], …]`), `graph_source` (`lockfile|depsdev|none`), `imported bool NULL` (path head imported by app source).
- `project_version_components`: `direct`, `depth`, `dev`.
- `project_version_dependencies(id, tenant_id, project_version_id, manifest_path, parent_component_id NULL=app, child_component_id, graph_source)` — full scans replace it.
- `projects`: `license` (SPDX expr), `license_source`, `usage_model` (`internal|saas|distributed_binary|distributed_source`, default `distributed_binary`).
- `policy_violations`: `severity` (`critical|high|medium|low|info`), `blocking bool` (counts toward failing the check), `details jsonb`. Suspicious/license findings are rows with `category` `suspicious` / `license`.
- Global caches: `depsdev_graph`, `package_latest`, `guarddog_verdict`. Views: `q_project_components`, `q_policy_violations` (new cols), `q_dependency_edges`, `q_scan_packages`.

### Go APIs
```go
// A — internal/scan
type DirectDep struct{ Name, Version string; Dev bool }       // from manifests
func ReadDirectDeps(ecosystem string, files map[string][]byte) []DirectDep // package.json, go.mod, pom.xml, Cargo.toml, pyproject.toml, requirements*.txt, Gemfile, composer.json
type GraphInfo struct{ Direct bool; Depth int; Dev bool; Paths [][]*models.Package /* ≤3, root first, ends with pkg */ }
type Graph struct{ /* … */ }
func BuildGraph(m *models.PackageManifest, direct []DirectDep) *Graph // lockfile graph; else direct set only
func (g *Graph) Info(p *models.Package) (GraphInfo, bool)
func (g *Graph) Source() string                                      // lockfile | depsdev | none
func (g *Graph) Edges() [][2]*models.Package                          // parent nil = app
func ImportedPackages(files map[string][]byte) map[string]bool        // normalized dep names imported by source
// A — internal/enrich
func (e *Enricher) DepsDevGraph(ctx, eco, name, version string) (nodes []GraphNode, edges [][2]int, err error) // cached depsdev_graph
// Match gains FixedIn string (first OSV fixed version above installed; "" if none)

// B — internal/suspicious
type Config struct{ Typosquat, Unmaintained, Deprecated, NewPackage, NoRepo, UnusualBehaviour bool; UnmaintainedMonths int; Blocking map[string]bool }
func ConfigFromPolicy(p scan.PolicyConfig) Config
func New(pool *pgxpool.Pool, e *enrich.Enricher, cfg Config) scan.Checker // rules: typosquat, deprecated, unmaintained, new-package, no-source-repo
func Prioritize(pkgs []*models.Package, findings []scan.Finding) []*models.Package // guarddog order
// B — internal/engine/guarddog.go: worker checks/writes guarddog_verdict; issues>0 → package_analyses suspicious
//      AND a policy_violations row (category suspicious, rule unusual-behaviour, details.rules).

// C — internal/license
type Detection struct{ Expr, Source string }
func DetectProject(files map[string][]byte, githubSPDX string) Detection // manifest > LICENSE text (licensecheck) > github > unknown
func New(cfg Config) scan.Checker // rules: license-unknown, license-copyleft-distributed, license-network-copyleft, license-weak-copyleft, license-noncommercial, license-incompatible (project↔dep via OSADL), license-conflict (dep↔dep)
type Config struct{ Deny []string /* extra denied SPDX prefixes from policy */ }
func Explain(spdx string) (category, summary string)                // for UI/report
```
Engine (A) wiring per scan: parse → BuildGraph (+deps.dev fallback for direct deps when the lockfile has no graph) → Enrich → CEL policy → `suspicious.New(...).Check` + `license.New(...).Check` with `CheckInput{Project, Packages, Context}` → persist findings (`severity`, `blocking`, `details`) → conclusion = failure iff any **blocking** finding/violation in block mode → render. Project license: `projects.license` override wins over `DetectProject`. Default CEL `risky-license` rule is removed in favour of `license-*` rules (B edits `DefaultRules`).

### Policy JSON additions (`/api/v1/policy`)
```json
{"presets": {
  "suspicious": {"typosquat": true, "unmaintained": true, "unmaintained_months": 24, "deprecated": true,
                 "new_package": true, "no_source_repo": false, "unusual_behaviour": true,
                 "blocking": ["typosquat", "unusual-behaviour"]},
  "license": {"deny": ["…"], "enabled": true, "blocking_severity": "high"}}}
```

### REST additions (service JWT, tenant)
| Method & path | Response |
|---|---|
| version components / components lists | items add `direct` (bool\|null), `depth`, `dev`; filter `direct=true\|false` |
| GET `/projects/{id}/versions/{vid}/paths?target=<component_id>&advisory=<id>` | `{source, nodes:[{id,name,version,ecosystem,direct,depth,vulns,max_risk,malware,suspicious,license_issue}], edges:[{from,to}] /* from "app" or component id */, paths:[PathItem]}` |
| GET `/scans/{id}/paths` | `{paths:[PathItem]}` from `scan_packages.paths` |
| GET `/vulnerabilities/{id}/paths` | `{items:[{project:{id,name}, version, paths:[PathItem]}]}` |
| GET/PUT `/projects/{id}/settings` | `{license, license_source, detected_license, usage_model}` (PUT: `license` override or null, `usage_model`; admin/owner) |
| GET `/scans/{id}/report?format=md\|json\|html` | full combined report (Content-Disposition attachment) |
| GET `/projects/{id}/versions/{vid}/licenses` | `{project_license, usage_model, findings:[{rule,severity,summary,component,details}], distribution:[{license,count,category}]}` |
| GET `/dashboard` | adds `transitive_vulnerabilities, attack_paths, suspicious_findings, license_issues` |
| `/scans/{id}` packages | add `direct, depth, dev, via, paths, imported, licenses, graph_source`; top-level `findings:[{rule,category,severity,blocking,summary,component,details}]` |
| `/policy/violations` items | add `severity, blocking, details`; filter `category=suspicious\|license`, `severity=` |
```
PathItem = {chain:[{name,version,component_id|null}], target:{name,version,component_id}, advisories:[{id,risk,epss,kev,fixed_in}],
            risk:"CRITICAL|HIGH|MEDIUM|LOW", score:0-100, depth:int, direct_head:"name@version", imported:bool|null,
            dev:bool, approximate:bool, fix:"Upgrade qs to ≥6.10.3 (via express ≥4.17.3)"}
```
Path score (computed at read time): base C=40,H=30,M=15,L=5 (max over advisories) + 20·KEV + 20·EPSS; × (imported true 1.0 / null 0.6 / false 0.3) × (dev 0.5) × max(0.5, 1 − 0.05·(depth−1)); clamp 0–100; MAL- target = 100.

### Machine / CLI
- `GET /v1/scans/{id}/report?format=md|json|html` (API key).
- CLI `depguard scan` also uploads manifests (`package.json`, `go.mod`, `pom.xml`, `Cargo.toml`, `pyproject.toml`, `Gemfile`, `composer.json`) and root `LICENSE*`/`COPYING*`; flags `--format md|json|report`, `--report-out <file.md|.json|.html>`, `--project-license <spdx>`, `--usage-model <model>` (sent as multipart fields `project_license`, `usage_model`; stored on the project).
