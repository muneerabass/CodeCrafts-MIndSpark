-- +goose Up
-- Attack-path and scan-report queries look up a scan's violations per component.
CREATE INDEX IF NOT EXISTS policy_violations_scan_id_component_id_idx ON policy_violations (scan_id, component_id);

-- +goose Down
DROP INDEX IF EXISTS policy_violations_scan_id_component_id_idx;
