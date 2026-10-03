-- +goose Up
-- System access paths that must work before a tenant is known (API-key auth)
-- or across tenants (super-admin tenant list). Each is a narrow SECURITY
-- DEFINER function owned by the migration owner; only depguard_app may call it.
--
-- Tables have FORCE ROW LEVEL SECURITY, which also binds the owner unless it
-- is a superuser, so the owner gets read-only policies on exactly the tables
-- these functions read. depguard_app/depguard_query cannot assume the owner role.
DROP POLICY IF EXISTS owner_system_read ON api_keys;
CREATE POLICY owner_system_read ON api_keys FOR SELECT TO CURRENT_USER USING (true);
DROP POLICY IF EXISTS owner_system_read ON tenant_settings;
CREATE POLICY owner_system_read ON tenant_settings FOR SELECT TO CURRENT_USER USING (true);
DROP POLICY IF EXISTS owner_system_read ON projects;
CREATE POLICY owner_system_read ON projects FOR SELECT TO CURRENT_USER USING (true);

-- API key lookup by sha256(key). Returns at most one row.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION depguard_api_key_lookup(p_hash bytea)
RETURNS TABLE (id text, tenant_id text, key_hash bytea, revoked_at timestamptz,
               expires_at timestamptz, tenant_disabled boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT k.id, k.tenant_id, k.key_hash, k.revoked_at, k.expires_at,
         COALESCE(t.disabled_at IS NOT NULL, false)
  FROM api_keys k LEFT JOIN tenant_settings t ON t.tenant_id = k.tenant_id
  WHERE k.key_hash = p_hash
$$;
-- +goose StatementEnd

-- Super-admin tenant list with project counts.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION depguard_admin_tenants()
RETURNS TABLE (tenant_id text, domain text, plan text, disabled_at timestamptz,
               created_at timestamptz, projects bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT t.tenant_id, t.domain, t.plan, t.disabled_at, t.created_at,
         (SELECT count(*) FROM projects p WHERE p.tenant_id = t.tenant_id)
  FROM tenant_settings t
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION depguard_api_key_lookup(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION depguard_admin_tenants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION depguard_api_key_lookup(bytea) TO depguard_app;
GRANT EXECUTE ON FUNCTION depguard_admin_tenants() TO depguard_app;

-- Query page hardening: a SELECT could call set_config('app.tenant', ...)
-- (directly or through dynamic-SQL functions such as ts_stat) and switch
-- tenants. Only roles that legitimately set the tenant keep EXECUTE; the query
-- executor uses SET LOCAL instead. Needs superuser (the docker POSTGRES_USER
-- is); otherwise it warns and the executor's statement checks remain the guard.
-- +goose StatementBegin
DO $$
BEGIN
  REVOKE EXECUTE ON FUNCTION pg_catalog.set_config(text, text, boolean) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION pg_catalog.set_config(text, text, boolean) TO depguard_app;
  EXECUTE format('GRANT EXECUTE ON FUNCTION pg_catalog.set_config(text, text, boolean) TO %I', current_user);
EXCEPTION WHEN insufficient_privilege THEN
  RAISE WARNING 'depguard: cannot revoke set_config from PUBLIC (not superuser); query role can switch tenants via set_config';
END $$;
-- +goose StatementEnd

-- +goose Down
GRANT EXECUTE ON FUNCTION pg_catalog.set_config(text, text, boolean) TO PUBLIC;
DROP FUNCTION IF EXISTS depguard_admin_tenants();
DROP FUNCTION IF EXISTS depguard_api_key_lookup(bytea);
DROP POLICY IF EXISTS owner_system_read ON projects;
DROP POLICY IF EXISTS owner_system_read ON tenant_settings;
DROP POLICY IF EXISTS owner_system_read ON api_keys;
