-- +goose Up
-- Lowest fixed version above the installed one (from OSV ranges), for fix advice.
ALTER TABLE component_vulnerabilities ADD COLUMN fixed_in text;
CREATE OR REPLACE VIEW q_component_vulnerabilities WITH (security_invoker = true) AS
  SELECT component_id, advisory_id, risk, first_seen, fixed_in FROM component_vulnerabilities;

-- +goose Down
DROP VIEW q_component_vulnerabilities;
CREATE VIEW q_component_vulnerabilities WITH (security_invoker = true) AS
  SELECT component_id, advisory_id, risk, first_seen FROM component_vulnerabilities;
GRANT SELECT ON q_component_vulnerabilities TO depguard_query;
ALTER TABLE component_vulnerabilities DROP COLUMN fixed_in;
