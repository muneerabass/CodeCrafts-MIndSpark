-- +goose Up
-- "Ask depguard" assistant: private conversations, and a narrower SQL surface
-- for AI-written queries.
--
-- depguard_query can read whole base tables behind the security_invoker q_*
-- views (report_md, payloads, evidence...). AI queries run as depguard_ai
-- (SET LOCAL ROLE): it may read the q_* views and only the base-table columns
-- those views use, so RLS still applies and hidden columns stay hidden.

-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'depguard_ai') THEN
    CREATE ROLE depguard_ai NOLOGIN;
  END IF;
END $$;
-- +goose StatementEnd
GRANT depguard_ai TO depguard_query;

-- New views run with the owner's rights and filter the tenant explicitly, so
-- the AI needs no grant on vault_items (hashes, ciphertext) or fix_prs.
CREATE VIEW q_fix_prs AS
  SELECT id, project_id, ecosystem, name, from_version, to_version, manifest_path, direct, advisories,
         pr_number, pr_url, status, error, created_at, updated_at
  FROM fix_prs WHERE tenant_id = current_setting('app.tenant', true);
CREATE VIEW q_vault_items AS
  SELECT id, project_id, name, kind, version, size,
         jsonb_path_query_array(fingerprints, '$[*].name') AS key_names, created_at, updated_at
  FROM vault_items WHERE tenant_id = current_setting('app.tenant', true);
CREATE VIEW q_exclusions AS
  SELECT id, ecosystem, name, version, reason, expires_at, created_at
  FROM exclusions WHERE tenant_id = current_setting('app.tenant', true);
CREATE VIEW q_advisory_aliases AS SELECT advisory_id, alias FROM advisory_alias;

-- +goose StatementBegin
DO $$
DECLARE v text; c record;
BEGIN
  FOREACH v IN ARRAY ARRAY['q_fix_prs','q_vault_items','q_exclusions','q_advisory_aliases'] LOOP
    EXECUTE format('GRANT SELECT ON %I TO depguard_query', v);
  END LOOP;
  FOR v IN SELECT table_name FROM information_schema.views
           WHERE table_schema = current_schema() AND table_name LIKE 'q\_%' LOOP
    EXECUTE format('GRANT SELECT ON %I TO depguard_ai', v);
  END LOOP;
  -- Column grants for the security_invoker views (checked as the invoker).
  FOR c IN SELECT u.table_name, u.column_name FROM information_schema.view_column_usage u
           JOIN pg_class k ON k.relname = u.view_name AND k.relnamespace = current_schema()::regnamespace
           WHERE u.view_schema = current_schema() AND u.view_name LIKE 'q\_%'
             AND 'security_invoker=true' = ANY (k.reloptions) LOOP
    EXECUTE format('GRANT SELECT (%I) ON %I TO depguard_ai', c.column_name, c.table_name);
  END LOOP;
END $$;
-- +goose StatementEnd

ALTER TABLE tenant_settings ADD COLUMN assistant jsonb NOT NULL DEFAULT '{}'; -- {"enabled": false} turns it off

CREATE TABLE assistant_conversations (
  id         text PRIMARY KEY,                -- ULID
  tenant_id  text NOT NULL,
  user_id    text NOT NULL,
  title      text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON assistant_conversations (tenant_id, user_id, updated_at DESC);

CREATE TABLE assistant_messages (
  id              text PRIMARY KEY,           -- ULID (sorts by time)
  tenant_id       text NOT NULL,
  conversation_id text NOT NULL REFERENCES assistant_conversations(id) ON DELETE CASCADE,
  role            text NOT NULL CHECK (role IN ('user','assistant')),
  text            text NOT NULL DEFAULT '',
  steps           jsonb NOT NULL DEFAULT '[]', -- [{tool, label, sql}]
  sources         jsonb NOT NULL DEFAULT '[]', -- [{title, url}]
  model           text NOT NULL DEFAULT '',
  input_tokens    int NOT NULL DEFAULT 0,
  output_tokens   int NOT NULL DEFAULT 0,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON assistant_messages (conversation_id, id);
CREATE INDEX ON assistant_messages (tenant_id, created_at);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['assistant_conversations','assistant_messages'] LOOP
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
ALTER TABLE tenant_settings DROP COLUMN assistant;
DROP TABLE assistant_messages;
DROP TABLE assistant_conversations;
DROP VIEW q_fix_prs, q_vault_items, q_exclusions, q_advisory_aliases;
-- +goose StatementBegin
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT DISTINCT table_name FROM information_schema.column_privileges WHERE grantee = 'depguard_ai' LOOP
    EXECUTE format('REVOKE ALL ON %I FROM depguard_ai', r.table_name);
  END LOOP;
END $$;
-- +goose StatementEnd
REVOKE depguard_ai FROM depguard_query;
