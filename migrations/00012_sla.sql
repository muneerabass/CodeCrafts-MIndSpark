-- +goose Up
-- Fix deadlines: when a vulnerable component stops being used by any project
-- version it is resolved; seen_current marks rows that were ever in the
-- current inventory (PR-only packages never count as fixed).
ALTER TABLE component_vulnerabilities ADD COLUMN resolved_at timestamptz;
ALTER TABLE component_vulnerabilities ADD COLUMN seen_current boolean NOT NULL DEFAULT false;
CREATE INDEX ON project_version_components (component_id);
UPDATE component_vulnerabilities cv SET seen_current = true
  WHERE EXISTS (SELECT 1 FROM project_version_components pvc WHERE pvc.component_id = cv.component_id);

-- Days to fix by risk level; {} = defaults (critical 7, high 30, medium 90, low none).
ALTER TABLE tenant_settings ADD COLUMN sla jsonb NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE tenant_settings DROP COLUMN sla;
DROP INDEX IF EXISTS project_version_components_component_id_idx;
ALTER TABLE component_vulnerabilities DROP COLUMN seen_current;
ALTER TABLE component_vulnerabilities DROP COLUMN resolved_at;
