-- +goose Up
-- End-to-end encrypted project vault. The server stores only public keys,
-- wrapped (encrypted) keys and ciphertext; it can never decrypt anything.
--   member key pair : ECDH P-256; private key encrypted with the member's vault
--                     passphrase (PBKDF2-SHA256 + AES-256-GCM) in the browser.
--   project vault key: random AES-256 key, wrapped per member (ECDH + HKDF + AES-GCM).
--   items           : AES-256-GCM with the vault key.
CREATE TABLE vault_members (
  tenant_id       text NOT NULL,
  user_id         text NOT NULL,
  email           text NOT NULL DEFAULT '',
  public_key      text NOT NULL,              -- base64 raw P-256 point
  wrapped_private jsonb NOT NULL,             -- {salt, iterations, iv, ciphertext}
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE vault_keys (
  tenant_id   text NOT NULL,
  project_id  text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id     text NOT NULL,
  key_version int NOT NULL,
  wrapped     jsonb NOT NULL,                 -- {ephemeral_public, iv, ciphertext}
  granted_by  text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (project_id, user_id)
);

CREATE TABLE vault_items (
  id           text PRIMARY KEY,              -- ULID
  tenant_id    text NOT NULL,
  project_id   text NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name         text NOT NULL,                 -- ".env.production", "gcp-sa.json"
  kind         text NOT NULL DEFAULT 'env' CHECK (kind IN ('env','file')),
  version      int NOT NULL DEFAULT 1,
  key_version  int NOT NULL,
  iv           text NOT NULL,
  ciphertext   text NOT NULL,                 -- base64
  size         int NOT NULL DEFAULT 0,        -- plaintext bytes
  fingerprints jsonb NOT NULL DEFAULT '[]',   -- [{"name": "STRIPE_KEY", "sha256": "..."}] of secret values, for leak matching
  created_by   text NOT NULL DEFAULT '',
  updated_by   text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, name)
);

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['vault_members','vault_keys','vault_items']
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
DROP TABLE vault_items;
DROP TABLE vault_keys;
DROP TABLE vault_members;
