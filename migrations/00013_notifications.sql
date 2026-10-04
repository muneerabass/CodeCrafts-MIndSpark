-- +goose Up
-- Alerts (Slack, email), weekly digest and Jira. Non-secret settings live in
-- tenant_settings.notifications; the Slack webhook URL and Jira token are
-- encrypted (secretbox, DEPGUARD_SECRET_KEY) in tenant_secrets.
ALTER TABLE tenant_settings ADD COLUMN notifications jsonb NOT NULL DEFAULT '{}';

CREATE TABLE tenant_secrets (
  tenant_id  text NOT NULL,
  name       text NOT NULL,
  ciphertext bytea NOT NULL,
  hint       text NOT NULL DEFAULT '',   -- safe to show, e.g. "…/B0X/abc1"
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, name)
);

-- Alert keys already delivered (malware:<component>, vuln:<component>:<advisory>, pr:<id>:<sha>, digest:<week>).
CREATE TABLE notifications_sent (
  tenant_id text NOT NULL,
  key       text NOT NULL,
  sent_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, key)
);

CREATE TABLE jira_links (
  tenant_id  text NOT NULL,
  ref_kind   text NOT NULL CHECK (ref_kind IN ('vuln','package')),
  ref        text NOT NULL,
  issue_key  text NOT NULL,
  url        text NOT NULL,
  created_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, ref_kind, ref)
);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenant_secrets','notifications_sent','jira_links']
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

-- +goose Down
DROP TABLE jira_links;
DROP TABLE notifications_sent;
DROP TABLE tenant_secrets;
ALTER TABLE tenant_settings DROP COLUMN notifications;
