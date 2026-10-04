-- +goose Up
-- Who changed what: every successful change made through the dashboard, the
-- API (keys) and super-admins. Request bodies are never stored (they can hold secrets).
CREATE TABLE audit_log (
  id          text PRIMARY KEY,              -- ULID
  tenant_id   text NOT NULL,
  actor_id    text NOT NULL DEFAULT '',
  actor_email text NOT NULL DEFAULT '',
  actor_role  text NOT NULL DEFAULT '',
  actor_kind  text NOT NULL DEFAULT 'user' CHECK (actor_kind IN ('user','api_key','admin','system')),
  action      text NOT NULL,                 -- "PUT /policy", "web:member.role", ...
  target_type text NOT NULL DEFAULT '',
  target_id   text NOT NULL DEFAULT '',
  details     jsonb NOT NULL DEFAULT '{}',
  ip          text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON audit_log (tenant_id, created_at DESC);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_log
  USING (tenant_id = current_setting('app.tenant', true))
  WITH CHECK (tenant_id = current_setting('app.tenant', true));
GRANT SELECT, INSERT, DELETE ON audit_log TO depguard_app;

-- +goose Down
DROP TABLE audit_log;
