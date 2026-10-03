-- +goose Up
-- Risk analysis: dependency paths (direct/transitive, attack paths), suspicious
-- packages and license compliance. See docs/CONTRACTS.md "Risk analysis".

-- Per-scan package context. via = shortest chain from the app, root first,
-- each element "name@version"; the last element is the package itself.
ALTER TABLE scan_packages
  ADD COLUMN direct       boolean,          -- NULL = unknown (no graph)
  ADD COLUMN depth        int,              -- 1 = direct dependency
  ADD COLUMN dev          boolean,          -- dev/test-only dependency
  ADD COLUMN via          text[] NOT NULL DEFAULT '{}',
  ADD COLUMN paths        jsonb  NOT NULL DEFAULT '[]'::jsonb, -- up to 3 chains (text[][]) incl. via
  ADD COLUMN graph_source text,             -- lockfile | depsdev | none
  ADD COLUMN imported     boolean;          -- head of path imported by app code; NULL = unknown

ALTER TABLE project_version_components
  ADD COLUMN direct boolean,
  ADD COLUMN depth  int,
  ADD COLUMN dev    boolean;

-- Dependency edges of a project version's current graph (full scans only).
-- parent_component_id NULL means "the application itself" (a direct dependency).
CREATE TABLE project_version_dependencies (
  id                  bigserial PRIMARY KEY,
  tenant_id           text NOT NULL,
  project_version_id  text NOT NULL REFERENCES project_versions(id) ON DELETE CASCADE,
  manifest_path       text NOT NULL,
  parent_component_id text REFERENCES components(id) ON DELETE CASCADE,
  child_component_id  text NOT NULL REFERENCES components(id) ON DELETE CASCADE,
  graph_source        text NOT NULL DEFAULT 'lockfile'
);
CREATE UNIQUE INDEX project_version_dependencies_uniq ON project_version_dependencies
  (project_version_id, manifest_path, COALESCE(parent_component_id, ''), child_component_id);
CREATE INDEX ON project_version_dependencies (tenant_id, child_component_id);
CREATE INDEX ON project_version_dependencies (project_version_id, parent_component_id);

-- Project license and how the project is used (drives license rules).
ALTER TABLE projects
  ADD COLUMN license        text,           -- SPDX expression
  ADD COLUMN license_source text,           -- override | manifest | license_file | github | unknown
  ADD COLUMN usage_model    text NOT NULL DEFAULT 'distributed_binary'
    CHECK (usage_model IN ('internal', 'saas', 'distributed_binary', 'distributed_source'));

-- Findings: suspicious (category 'suspicious') and license ('license') findings
-- reuse policy_violations so gating, lists, dashboard and Query keep working.
ALTER TABLE policy_violations
  ADD COLUMN severity text NOT NULL DEFAULT 'high'
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  ADD COLUMN blocking boolean NOT NULL DEFAULT true,  -- counts toward check failure
  ADD COLUMN details  jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX ON policy_violations (tenant_id, category);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['project_version_dependencies']
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
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO depguard_app;

-- ------------------------------------------------- global caches (no RLS)
-- deps.dev resolved dependency graph of a package version (fallback paths).
CREATE TABLE depsdev_graph (
  system     text NOT NULL,                  -- deps.dev system: npm, pypi, go, maven, cargo, nuget, rubygems
  name       text NOT NULL,
  version    text NOT NULL,
  nodes      jsonb NOT NULL DEFAULT '[]'::jsonb, -- [{name, version, relation}]
  edges      jsonb NOT NULL DEFAULT '[]'::jsonb, -- [{from, to}] node indexes
  found      boolean NOT NULL DEFAULT true,
  fetched_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (system, name, version)
);
-- Package-level maintenance signals from deps.dev GetPackage.
CREATE TABLE package_latest (
  ecosystem         text NOT NULL,           -- OSV ecosystem name
  name_norm         text NOT NULL,
  default_version   text,
  latest_published  timestamptz,
  deprecated        boolean NOT NULL DEFAULT false, -- default version deprecated
  deprecated_versions text[] NOT NULL DEFAULT '{}',
  deprecated_reason text,
  found             boolean NOT NULL DEFAULT true,
  fetched_at        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ecosystem, name_norm)
);
-- guarddog verdicts shared across tenants (a package version is analysed once).
CREATE TABLE guarddog_verdict (
  ecosystem   text NOT NULL,
  name        text NOT NULL,
  version     text NOT NULL,
  issues      int NOT NULL DEFAULT 0,
  rules       text[] NOT NULL DEFAULT '{}', -- rule names that fired
  results     jsonb NOT NULL DEFAULT '{}'::jsonb,
  error       text,
  analyzed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ecosystem, name, version)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON depsdev_graph, package_latest, guarddog_verdict TO depguard_app;

-- ---------------------------------------------------------- query views
CREATE OR REPLACE VIEW q_project_components WITH (security_invoker = true) AS
  SELECT project_version_id, component_id, manifest_path, updated_at, direct, depth, dev
  FROM project_version_components;
CREATE OR REPLACE VIEW q_policy_violations WITH (security_invoker = true) AS
  SELECT id, scan_id, project_version_id, component_id, rule_name, category, summary, created_at,
         severity, blocking, details
  FROM policy_violations;
CREATE VIEW q_dependency_edges WITH (security_invoker = true) AS
  SELECT project_version_id, manifest_path, parent_component_id, child_component_id, graph_source
  FROM project_version_dependencies;
CREATE VIEW q_scan_packages WITH (security_invoker = true) AS
  SELECT scan_id, component_id, manifest_path, change, malware, vulnerable, risky_license,
         direct, depth, dev, via, graph_source, imported
  FROM scan_packages;
GRANT SELECT ON q_dependency_edges, q_scan_packages TO depguard_query;
GRANT SELECT ON project_version_dependencies, scan_packages TO depguard_query;

-- +goose Down
DROP VIEW IF EXISTS q_scan_packages, q_dependency_edges, q_project_components, q_policy_violations;
CREATE VIEW q_project_components WITH (security_invoker = true) AS
  SELECT project_version_id, component_id, manifest_path, updated_at FROM project_version_components;
CREATE VIEW q_policy_violations WITH (security_invoker = true) AS
  SELECT id, scan_id, project_version_id, component_id, rule_name, category, summary, created_at FROM policy_violations;
GRANT SELECT ON q_project_components, q_policy_violations TO depguard_query;
DROP TABLE IF EXISTS guarddog_verdict, package_latest, depsdev_graph, project_version_dependencies;
ALTER TABLE policy_violations DROP COLUMN details, DROP COLUMN blocking, DROP COLUMN severity;
ALTER TABLE projects DROP COLUMN usage_model, DROP COLUMN license_source, DROP COLUMN license;
ALTER TABLE project_version_components DROP COLUMN dev, DROP COLUMN depth, DROP COLUMN direct;
ALTER TABLE scan_packages DROP COLUMN imported, DROP COLUMN graph_source, DROP COLUMN paths,
  DROP COLUMN via, DROP COLUMN dev, DROP COLUMN depth, DROP COLUMN direct;
