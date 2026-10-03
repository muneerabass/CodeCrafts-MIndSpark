-- +goose Up
-- Fix pull requests opened by depguard (button or auto mode).
CREATE TABLE fix_prs (
  id            text PRIMARY KEY,
  tenant_id     text NOT NULL,
  project_id    text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  ecosystem     text NOT NULL,
  name          text NOT NULL,
  from_version  text NOT NULL,
  to_version    text NOT NULL,
  manifest_path text NOT NULL,
  direct        boolean NOT NULL DEFAULT true,
  advisories    text[] NOT NULL DEFAULT '{}',
  branch        text NOT NULL DEFAULT '',
  pr_number     int,
  pr_url        text NOT NULL DEFAULT '',
  status        text NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','open','merged','closed','failed','unsupported')),
  error         text NOT NULL DEFAULT '',
  trigger       text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual','auto')),
  created_by    text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX fix_prs_active ON fix_prs (project_id, ecosystem, name, to_version, manifest_path)
  WHERE status IN ('queued','open');
CREATE INDEX ON fix_prs (tenant_id, created_at DESC);

-- Auto-fix settings; {} = defaults (off).
ALTER TABLE tenant_settings ADD COLUMN fix_settings jsonb NOT NULL DEFAULT '{}';

ALTER TABLE fix_prs ENABLE ROW LEVEL SECURITY;
ALTER TABLE fix_prs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON fix_prs
  USING (tenant_id = current_setting('app.tenant', true))
  WITH CHECK (tenant_id = current_setting('app.tenant', true));
GRANT SELECT, INSERT, UPDATE, DELETE ON fix_prs TO depguard_app;

-- +goose Down
ALTER TABLE tenant_settings DROP COLUMN fix_settings;
DROP TABLE fix_prs;
