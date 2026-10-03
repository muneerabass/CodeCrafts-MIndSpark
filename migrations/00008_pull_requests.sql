-- +goose Up
-- Pull requests of connected GitHub repositories: metadata from webhooks and
-- backfill, the urgency computed from the latest scan and review, and labels.
-- The project is derived from repo_id (projects.gh_repo_id).
CREATE TABLE pull_requests (
  id             text PRIMARY KEY,                 -- ULID
  tenant_id      text NOT NULL,
  repo_id        bigint NOT NULL,
  repo_full_name text NOT NULL,
  number         int NOT NULL,
  title          text NOT NULL DEFAULT '',
  author_login   text NOT NULL DEFAULT '',
  author_avatar  text NOT NULL DEFAULT '',
  html_url       text NOT NULL DEFAULT '',
  state          text NOT NULL DEFAULT 'open' CHECK (state IN ('open','closed','merged')),
  draft          boolean NOT NULL DEFAULT false,
  base_ref       text NOT NULL DEFAULT '',
  head_ref       text NOT NULL DEFAULT '',
  head_sha       text NOT NULL DEFAULT '',
  base_sha       text NOT NULL DEFAULT '',
  installation_id bigint,
  gh_created_at  timestamptz,
  gh_updated_at  timestamptz,
  closed_at      timestamptz,
  merged_at      timestamptz,
  latest_scan_id text,
  urgency        int NOT NULL DEFAULT 0,           -- 0-100, higher = fix sooner
  urgency_level  text NOT NULL DEFAULT 'pending'
                 CHECK (urgency_level IN ('critical','high','medium','low','clean','pending')),
  reasons        jsonb NOT NULL DEFAULT '[]',       -- [{kind, text}] top reasons
  labels         text[] NOT NULL DEFAULT '{}',      -- depguard labels, without prefix
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, repo_id, number)
);
CREATE INDEX ON pull_requests (tenant_id, state, urgency DESC);
CREATE INDEX ON pull_requests (tenant_id, repo_id, state);

-- One review per PR head commit: rule-based findings (always) and the AI
-- review (when configured), with labels from both.
CREATE TABLE pr_reviews (
  id            text PRIMARY KEY,
  tenant_id     text NOT NULL,
  pr_id         text NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
  scan_id       text,
  head_sha      text NOT NULL,
  findings      jsonb NOT NULL DEFAULT '[]',  -- [{source, file, line, severity, category, title, explanation, suggestion}]
  labels        text[] NOT NULL DEFAULT '{}',
  files_reviewed int NOT NULL DEFAULT 0,
  truncated     boolean NOT NULL DEFAULT false,
  ai_status     text NOT NULL DEFAULT 'skipped'
                CHECK (ai_status IN ('queued','running','done','skipped','rate_limited','failed')),
  ai_note       text NOT NULL DEFAULT '',     -- why skipped/delayed/failed
  ai_model      text NOT NULL DEFAULT '',
  ai_summary    text NOT NULL DEFAULT '',
  ai_risk       text NOT NULL DEFAULT '',
  input_tokens  int NOT NULL DEFAULT 0,
  output_tokens int NOT NULL DEFAULT 0,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (pr_id, head_sha)
);

-- Actions taken from the dashboard and the re-run checkbox, posted by the worker.
CREATE TABLE pr_activity (
  id          text PRIMARY KEY,
  tenant_id   text NOT NULL,
  pr_id       text NOT NULL REFERENCES pull_requests(id) ON DELETE CASCADE,
  actor_email text NOT NULL DEFAULT '',
  kind        text NOT NULL CHECK (kind IN ('comment','request_changes','rescan','ai_review','accept_risk')),
  body        text NOT NULL DEFAULT '',
  status      text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','posted','failed')),
  gh_id       bigint,
  error       text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON pr_activity (pr_id, created_at DESC);

-- Compact dependency summary of a PR scan, so the comment can be re-rendered
-- when the AI review finishes without re-running the scan.
ALTER TABLE scans ADD COLUMN pr_summary jsonb;
CREATE INDEX ON scans (project_id, pr_number, created_at DESC);

-- Team PR settings (comment, labels, AI review); {} = defaults.
ALTER TABLE tenant_settings ADD COLUMN pr_settings jsonb NOT NULL DEFAULT '{}';

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['pull_requests','pr_reviews','pr_activity']
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

CREATE VIEW q_pull_requests WITH (security_invoker = true) AS
  SELECT id, repo_full_name, number, title, author_login, state, draft, base_ref, head_ref, head_sha,
         gh_created_at, gh_updated_at, closed_at, merged_at, latest_scan_id, urgency, urgency_level, labels
  FROM pull_requests;
GRANT SELECT ON q_pull_requests TO depguard_query;
GRANT SELECT ON pull_requests TO depguard_query;

-- +goose Down
DROP VIEW q_pull_requests;
ALTER TABLE tenant_settings DROP COLUMN pr_settings;
DROP INDEX IF EXISTS scans_project_id_pr_number_created_at_idx;
ALTER TABLE scans DROP COLUMN pr_summary;
DROP TABLE pr_activity;
DROP TABLE pr_reviews;
DROP TABLE pull_requests;
