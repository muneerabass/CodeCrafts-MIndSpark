-- +goose Up
-- Domain schema owned by the Go service. Better Auth (web) owns its own tables
-- (user, session, account, verification, organization, member, invitation).
-- tenant_id = Better Auth organization.id (text). No cross-owner FKs.

-- Roles: depguard_app (runtime, subject to RLS) and depguard_query (read-only,
-- Query page). Created idempotently; passwords set by deploy scripts.
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'depguard_app') THEN
    CREATE ROLE depguard_app LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'depguard_query') THEN
    CREATE ROLE depguard_query LOGIN;
  END IF;
END $$;
-- +goose StatementEnd

-- ---------------------------------------------------------------- tenants
CREATE TABLE tenant_settings (
  tenant_id               text PRIMARY KEY,
  domain                  text NOT NULL UNIQUE,          -- e.g. acme.depguard.dev
  plan                    text NOT NULL DEFAULT 'free',
  block_mode              boolean NOT NULL DEFAULT true, -- false = warn (neutral check)
  scan_draft_prs          boolean NOT NULL DEFAULT false,
  suppress_clean_comments boolean NOT NULL DEFAULT false,
  policy                  jsonb NOT NULL DEFAULT '{}'::jsonb, -- presets + custom CEL rules
  disabled_at             timestamptz,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
  id           text PRIMARY KEY,                 -- ULID
  tenant_id    text NOT NULL,
  name         text NOT NULL,
  prefix       text NOT NULL,                    -- first chars shown in UI, e.g. dg_live_ab12
  key_hash     bytea NOT NULL UNIQUE,            -- sha256(full key)
  created_by   text NOT NULL,                    -- Better Auth user.id
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at   timestamptz,
  revoked_at   timestamptz
);
CREATE INDEX ON api_keys (tenant_id);

-- --------------------------------------------------------------- github
CREATE TABLE gh_installations (
  id            bigint PRIMARY KEY,              -- GitHub installation id
  account_login text NOT NULL,
  account_type  text NOT NULL,                   -- Organization | User
  account_id    bigint NOT NULL,
  tenant_id     text,                            -- NULL while pending
  status        text NOT NULL DEFAULT 'pending', -- pending | linked | suspended | deleted
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON gh_installations (tenant_id);

CREATE TABLE gh_repositories (
  id              bigint PRIMARY KEY,            -- GitHub repository id
  installation_id bigint NOT NULL REFERENCES gh_installations(id) ON DELETE CASCADE,
  full_name       text NOT NULL,
  default_branch  text NOT NULL DEFAULT 'main',
  private         boolean NOT NULL DEFAULT false,
  removed_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON gh_repositories (installation_id);

-- Global admin view of incoming webhooks (no tenant until resolved).
CREATE TABLE webhook_deliveries (
  delivery_id     text PRIMARY KEY,              -- X-GitHub-Delivery (dedupe)
  event           text NOT NULL,
  action          text,
  installation_id bigint,
  repository      text,
  status          text NOT NULL DEFAULT 'received', -- received | enqueued | ignored | failed
  error           text,
  received_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON webhook_deliveries (received_at DESC);

-- ------------------------------------------------------------- inventory
CREATE TABLE projects (
  id         text PRIMARY KEY,                   -- ULID
  tenant_id  text NOT NULL,
  source     text NOT NULL,                      -- github | cli | gitlab | bitbucket
  name       text NOT NULL,                      -- e.g. owner/repo
  url        text,
  gh_repo_id bigint,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, source, name)
);

CREATE TABLE project_versions (
  id           text PRIMARY KEY,                 -- ULID
  tenant_id    text NOT NULL,
  project_id   text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name         text NOT NULL,                    -- branch / tag / env
  last_scan_id text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, name)
);

-- A component is a package@version within a tenant.
CREATE TABLE components (
  id         text PRIMARY KEY,                   -- ULID
  tenant_id  text NOT NULL,
  ecosystem  text NOT NULL,                      -- vet ecosystem name: npm, PyPI, Go, Maven, ...
  name       text NOT NULL,
  version    text NOT NULL,
  purl       text NOT NULL,
  type       text NOT NULL DEFAULT 'library',
  licenses   text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, purl)
);
CREATE INDEX ON components (tenant_id, name);

-- Current component set of a project version (replaced on each full scan).
CREATE TABLE project_version_components (
  tenant_id          text NOT NULL,
  project_version_id text NOT NULL REFERENCES project_versions(id) ON DELETE CASCADE,
  component_id       text NOT NULL REFERENCES components(id) ON DELETE CASCADE,
  manifest_path      text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (project_version_id, component_id, manifest_path)
);
CREATE INDEX ON project_version_components (tenant_id, component_id);

-- Vulnerabilities matched to a component (advisory details live in feeds tables).
CREATE TABLE component_vulnerabilities (
  tenant_id    text NOT NULL,
  component_id text NOT NULL REFERENCES components(id) ON DELETE CASCADE,
  advisory_id  text NOT NULL,                    -- OSV id (GHSA-, PYSEC-, MAL-, ...)
  risk         text NOT NULL,                    -- CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
  first_seen   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (component_id, advisory_id)
);
CREATE INDEX ON component_vulnerabilities (tenant_id, advisory_id);

CREATE TABLE scans (
  id                 text PRIMARY KEY,           -- ULID
  tenant_id          text NOT NULL,
  project_id         text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  project_version_id text NOT NULL REFERENCES project_versions(id) ON DELETE CASCADE,
  trigger            text NOT NULL,              -- manual | pull_request | push | cli
  status             text NOT NULL DEFAULT 'queued', -- queued | running | success | failed | skipped
  pr_number          int,
  head_sha           text,
  base_sha           text,
  check_run_id       bigint,
  comment_id         bigint,
  components_count   int NOT NULL DEFAULT 0,
  vulns_count        int NOT NULL DEFAULT 0,
  violations_count   int NOT NULL DEFAULT 0,
  malicious_count    int NOT NULL DEFAULT 0,
  suspicious_count   int NOT NULL DEFAULT 0,
  conclusion         text,                       -- success | failure | neutral
  report_md          text,                       -- rendered PR/scan report
  error              text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  started_at         timestamptz,
  finished_at        timestamptz
);
CREATE INDEX ON scans (tenant_id, created_at DESC);
CREATE INDEX ON scans (project_id, created_at DESC);

-- Packages evaluated by a scan (for PR scans: only new/changed ones).
CREATE TABLE scan_packages (
  tenant_id     text NOT NULL,
  scan_id       text NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  component_id  text NOT NULL REFERENCES components(id) ON DELETE CASCADE,
  manifest_path text NOT NULL,
  change        text NOT NULL DEFAULT 'full',    -- full | added | changed
  malware       boolean NOT NULL DEFAULT false,
  vulnerable    boolean NOT NULL DEFAULT false,
  risky_license boolean NOT NULL DEFAULT false,
  PRIMARY KEY (scan_id, component_id, manifest_path)
);

-- Lockfiles uploaded via POST /v1/scans, consumed by the scan_upload job.
CREATE TABLE scan_uploads (
  tenant_id text NOT NULL,
  scan_id   text NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  path      text NOT NULL,                       -- path inside the project
  content   bytea NOT NULL,
  PRIMARY KEY (scan_id, path)
);

CREATE TABLE policy_violations (
  id                 text PRIMARY KEY,           -- ULID
  tenant_id          text NOT NULL,
  scan_id            text NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  project_version_id text NOT NULL REFERENCES project_versions(id) ON DELETE CASCADE,
  component_id       text NOT NULL REFERENCES components(id) ON DELETE CASCADE,
  rule_name          text NOT NULL,
  category           text NOT NULL,              -- vulnerability | malware | license | popularity | maintenance
  summary            text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON policy_violations (tenant_id, created_at DESC);

CREATE TABLE package_analyses (
  id                 text PRIMARY KEY,           -- ULID
  tenant_id          text NOT NULL,
  component_id       text NOT NULL REFERENCES components(id) ON DELETE CASCADE,
  project_version_id text REFERENCES project_versions(id) ON DELETE CASCADE,
  scan_id            text REFERENCES scans(id) ON DELETE SET NULL,
  status             text NOT NULL,              -- clean | suspicious | malicious
  verified           boolean NOT NULL DEFAULT false,
  source             text NOT NULL,              -- osv | guarddog | admin
  evidence           jsonb NOT NULL DEFAULT '{}'::jsonb,
  verified_by        text,
  verified_at        timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON package_analyses (tenant_id, created_at DESC);

CREATE TABLE exclusions (
  id         text PRIMARY KEY,                   -- ULID
  tenant_id  text NOT NULL,
  ecosystem  text NOT NULL,
  name       text NOT NULL,
  version    text NOT NULL DEFAULT '*',          -- '*' = all versions
  reason     text NOT NULL,
  expires_at timestamptz,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON exclusions (tenant_id);

-- ------------------------------------------------------------ endpoints
CREATE TABLE endpoints (
  id            text PRIMARY KEY,                -- ULID
  tenant_id     text NOT NULL,
  identifier    text NOT NULL,                   -- agent-provided stable id
  endpoint_type text NOT NULL DEFAULT 'developer', -- developer | ci | agent_sandbox
  hostname      text,
  os            text,
  agent_version text,
  last_sync_at  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, identifier)
);

CREATE TABLE inventory_items (
  id          text PRIMARY KEY,
  tenant_id   text NOT NULL,
  endpoint_id text NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  kind        text NOT NULL,                     -- coding_agent | mcp_server | agent_skill | ide_extension | cli_tool
  name        text NOT NULL,
  version     text,
  scope       text,                              -- system | project
  config_path text,
  details     jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (endpoint_id, kind, name, config_path)
);

CREATE TABLE package_guard_events (
  id           bigserial PRIMARY KEY,
  tenant_id    text NOT NULL,
  endpoint_id  text NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  ts           timestamptz NOT NULL,
  event_type   text NOT NULL,                    -- pmg event_type, e.g. malware_blocked
  ecosystem    text,
  package_name text,
  version      text,
  message      text,
  details      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX ON package_guard_events (tenant_id, ts DESC);

CREATE TABLE agent_events (
  id            text PRIMARY KEY,                -- gryph event id
  tenant_id     text NOT NULL,
  endpoint_id   text NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  session_id    text NOT NULL,
  ts            timestamptz NOT NULL,
  agent_name    text NOT NULL,
  action_type   text NOT NULL,
  result_status text NOT NULL,
  tool_name     text,
  is_sensitive  boolean NOT NULL DEFAULT false,
  payload       jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX ON agent_events (tenant_id, ts DESC);

CREATE TABLE saved_queries (
  id         text PRIMARY KEY,
  tenant_id  text NOT NULL,
  name       text NOT NULL,
  sql        text NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ------------------------------------------------- feeds (global, no RLS)
CREATE TABLE advisory (
  id        text PRIMARY KEY,                    -- OSV id
  source    text NOT NULL,                       -- ecosystem dir in OSV bucket
  summary   text,
  details   text,
  severity  jsonb NOT NULL DEFAULT '[]'::jsonb,  -- OSV severity[]
  risk      text NOT NULL DEFAULT 'UNKNOWN',     -- derived from CVSS
  published timestamptz,
  modified  timestamptz NOT NULL,
  withdrawn timestamptz,
  is_malware boolean GENERATED ALWAYS AS (id LIKE 'MAL-%') STORED,
  raw       jsonb NOT NULL
);
CREATE TABLE advisory_alias (
  advisory_id text NOT NULL REFERENCES advisory(id) ON DELETE CASCADE,
  alias       text NOT NULL,
  PRIMARY KEY (advisory_id, alias)
);
CREATE INDEX ON advisory_alias (alias);
CREATE TABLE affected (
  id          bigserial PRIMARY KEY,
  advisory_id text NOT NULL REFERENCES advisory(id) ON DELETE CASCADE,
  ecosystem   text NOT NULL,                     -- OSV ecosystem name
  name_norm   text NOT NULL,                     -- normalized package name
  versions    text[] NOT NULL DEFAULT '{}',      -- explicit affected versions
  ranges      jsonb NOT NULL DEFAULT '[]'::jsonb -- OSV ranges[] (SEMVER/ECOSYSTEM events)
);
CREATE INDEX ON affected (ecosystem, name_norm);
CREATE TABLE cve_score (
  cve        text PRIMARY KEY,
  epss       real,
  percentile real,
  epss_date  date,
  kev        boolean NOT NULL DEFAULT false,
  kev_added  date,
  ransomware boolean NOT NULL DEFAULT false
);
CREATE TABLE package_meta (                      -- deps.dev cache
  ecosystem  text NOT NULL,
  name_norm  text NOT NULL,
  version    text NOT NULL,
  licenses   text[] NOT NULL DEFAULT '{}',
  repo       text,                               -- github.com/org/repo
  stars      int,
  forks      int,
  published_at timestamptz,
  fetched_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ecosystem, name_norm, version)
);
CREATE TABLE scorecard (
  repo       text PRIMARY KEY,
  score      real,
  checks     jsonb NOT NULL DEFAULT '{}'::jsonb,
  fetched_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sync_state (
  source  text PRIMARY KEY,                      -- osv:npm, kev, epss, ...
  cursor  text,
  etag    text,
  last_ok timestamptz,
  last_error text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- RLS
-- Every tenant table: app.tenant must match. Unset setting => no rows.
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenant_settings','api_keys','projects','project_versions',
    'components','project_version_components','component_vulnerabilities','scans',
    'scan_packages','scan_uploads','policy_violations','package_analyses','exclusions','endpoints',
    'inventory_items','package_guard_events','agent_events','saved_queries']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = current_setting('app.tenant', true))
      WITH CHECK (tenant_id = current_setting('app.tenant', true))$p$, t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO depguard_app', t);
  END LOOP;
END $$;
-- +goose StatementEnd

-- Global tables: app role may read/write (system jobs), query role reads advisories.
GRANT SELECT, INSERT, UPDATE, DELETE ON gh_installations, gh_repositories, webhook_deliveries,
  advisory, advisory_alias, affected, cve_score, package_meta, scorecard, sync_state TO depguard_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO depguard_app;

-- Query page: read-only views over tenant data (RLS still applies through
-- security_invoker views) plus advisory data.
CREATE VIEW q_projects WITH (security_invoker = true) AS
  SELECT id, name, source, url, created_at, updated_at FROM projects;
CREATE VIEW q_project_versions WITH (security_invoker = true) AS
  SELECT id, project_id, name, created_at FROM project_versions;
CREATE VIEW q_components WITH (security_invoker = true) AS
  SELECT id, ecosystem, name, version, purl, type, licenses, created_at, updated_at FROM components;
CREATE VIEW q_project_components WITH (security_invoker = true) AS
  SELECT project_version_id, component_id, manifest_path, updated_at FROM project_version_components;
CREATE VIEW q_component_vulnerabilities WITH (security_invoker = true) AS
  SELECT component_id, advisory_id, risk, first_seen FROM component_vulnerabilities;
CREATE VIEW q_scans WITH (security_invoker = true) AS
  SELECT id, project_id, project_version_id, trigger, status, pr_number, head_sha,
         components_count, vulns_count, violations_count, malicious_count, suspicious_count,
         conclusion, created_at, finished_at FROM scans;
CREATE VIEW q_policy_violations WITH (security_invoker = true) AS
  SELECT id, scan_id, project_version_id, component_id, rule_name, category, summary, created_at FROM policy_violations;
CREATE VIEW q_package_analyses WITH (security_invoker = true) AS
  SELECT id, component_id, project_version_id, scan_id, status, verified, source, created_at FROM package_analyses;
CREATE VIEW q_endpoints WITH (security_invoker = true) AS
  SELECT id, identifier, endpoint_type, hostname, os, last_sync_at, created_at FROM endpoints;
CREATE VIEW q_inventory_items WITH (security_invoker = true) AS
  SELECT id, endpoint_id, kind, name, version, scope, first_seen, last_seen FROM inventory_items;
CREATE VIEW q_package_guard_events WITH (security_invoker = true) AS
  SELECT id, endpoint_id, ts, event_type, ecosystem, package_name, version FROM package_guard_events;
CREATE VIEW q_agent_events WITH (security_invoker = true) AS
  SELECT id, endpoint_id, session_id, ts, agent_name, action_type, result_status, tool_name FROM agent_events;
CREATE VIEW q_vulnerabilities AS
  SELECT id, summary, risk, published, modified, is_malware FROM advisory WHERE withdrawn IS NULL;
CREATE VIEW q_cve_scores AS SELECT * FROM cve_score;

-- +goose StatementBegin
DO $$
DECLARE v text;
BEGIN
  FOREACH v IN ARRAY ARRAY['q_projects','q_project_versions','q_components','q_project_components',
    'q_component_vulnerabilities','q_scans','q_policy_violations','q_package_analyses','q_endpoints',
    'q_inventory_items','q_package_guard_events','q_agent_events','q_vulnerabilities','q_cve_scores']
  LOOP
    EXECUTE format('GRANT SELECT ON %I TO depguard_query', v);
  END LOOP;
END $$;
-- +goose StatementEnd
-- security_invoker views check base-table privileges as the query role.
GRANT SELECT ON projects, project_versions, components, project_version_components,
  component_vulnerabilities, scans, policy_violations, package_analyses, endpoints,
  inventory_items, package_guard_events, agent_events TO depguard_query;

-- +goose Down
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
