package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
)

// Current state of a project version = its last full scan (engine sets
// project_versions.last_scan_id; fall back to the latest successful non-PR
// scan). Violation counts come from that scan; component and vulnerability
// counts from the current project_version_components set. MAL- advisories are
// malware, not vulnerabilities, and are excluded from vuln counts.
const withCur = `WITH cur AS (
  SELECT pv.id AS pv_id, pv.project_id, pv.name AS pv_name,
    COALESCE(pv.last_scan_id, (SELECT s.id FROM scans s WHERE s.project_version_id = pv.id
      AND s.status = 'success' AND s.trigger <> 'pull_request' ORDER BY s.created_at DESC LIMIT 1)) AS scan_id
  FROM project_versions pv),
curv AS (SELECT pol.*, cur.project_id FROM policy_violations pol JOIN cur ON cur.scan_id = pol.scan_id) `

const notMal = `advisory_id NOT LIKE 'MAL-%'`

func componentJSON(alias string) string {
	return `jsonb_build_object('id', ` + alias + `.id, 'name', ` + alias + `.name, 'version', ` + alias + `.version, 'ecosystem', ` + alias + `.ecosystem)`
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler(withCur, `
SELECT p.id, p.name, p.source, p.url, p.created_at,
  (SELECT count(*) FROM project_versions v WHERE v.project_id = p.id) AS versions,
  (SELECT count(DISTINCT pvc.component_id) FROM project_version_components pvc
     JOIN project_versions v ON v.id = pvc.project_version_id WHERE v.project_id = p.id) AS components,
  (SELECT count(*) FROM curv WHERE curv.project_id = p.id) AS violations,
  (SELECT count(DISTINCT (x.component_id, x.advisory_id)) FROM component_vulnerabilities x
     JOIN project_version_components pvc ON pvc.component_id = x.component_id
     JOIN project_versions v ON v.id = pvc.project_version_id
     WHERE v.project_id = p.id AND x.`+notMal+`) AS vulns
FROM projects p`,
		filterSpec{eq: map[string]string{"source": "t.source"}, ilike: map[string]string{"name": "t.name"},
			dateCol: "t.created_at", vulns: true, viols: true},
		"t.created_at DESC, t.id", nil)(w, r)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `
SELECT jsonb_build_object('id', p.id, 'name', p.name, 'source', p.source, 'url', p.url, 'created_at', p.created_at,
  'versions', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', v.id, 'name', v.name, 'updated_at', v.updated_at,
      'last_scan_at', (SELECT max(s.created_at) FROM scans s WHERE s.project_version_id = v.id)) ORDER BY v.updated_at DESC)
    FROM project_versions v WHERE v.project_id = p.id), '[]'::jsonb))
FROM projects p WHERE p.id = $1`, r.PathValue("id"))
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// versionExtra restricts to the {vid} version of project {id}.
func versionExtra(col string) func(*http.Request, *where) error {
	return func(r *http.Request, w *where) error {
		w.add(col+" = ?", r.PathValue("vid"))
		w.add("EXISTS (SELECT 1 FROM project_versions pv WHERE pv.id = ? AND pv.project_id = ?)", r.PathValue("vid"), r.PathValue("id"))
		return nil
	}
}

func (s *Server) versionSummary(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, withCur+`
SELECT jsonb_build_object(
  'components', (SELECT count(DISTINCT component_id) FROM project_version_components WHERE project_version_id = v.id),
  'vulns', (SELECT count(DISTINCT x.advisory_id) FROM component_vulnerabilities x
     JOIN project_version_components pvc ON pvc.component_id = x.component_id
     WHERE pvc.project_version_id = v.id AND x.`+notMal+`),
  'violations', (SELECT count(*) FROM curv WHERE curv.project_version_id = v.id),
  'versions_available', (SELECT count(*) FROM project_versions o WHERE o.project_id = v.project_id),
  'updated_at', v.updated_at)
FROM project_versions v WHERE v.id = $1 AND v.project_id = $2`, r.PathValue("vid"), r.PathValue("id"))
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) versionComponents(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler(withCur, `
SELECT c.id, c.name, c.version, c.type, c.ecosystem, c.created_at, c.updated_at, pvc.project_version_id AS pv_id,
  pvc.direct, pvc.depth, pvc.dev,
  (SELECT count(*) FROM curv WHERE curv.project_version_id = pvc.project_version_id AND curv.component_id = c.id) AS violations,
  (SELECT count(*) FROM component_vulnerabilities x WHERE x.component_id = c.id AND x.`+notMal+`) AS vulns
FROM (SELECT project_version_id, component_id, bool_or(direct) AS direct, min(depth) AS depth, bool_and(dev) AS dev
      FROM project_version_components GROUP BY project_version_id, component_id) pvc
JOIN components c ON c.id = pvc.component_id`,
		filterSpec{ilike: map[string]string{"name": "t.name"}, eq: map[string]string{"ecosystem": "t.ecosystem"}, vulns: true, viols: true},
		"t.name, t.version", extras(versionExtra("t.pv_id"), boolParam("direct", "t.direct")), "pv_id")(w, r)
}

func (s *Server) versionVulns(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `
SELECT DISTINCT ON (pvc.project_version_id, x.advisory_id) x.advisory_id AS id, a.summary, COALESCE(a.risk, x.risk) AS risk,
  a.published, a.modified, pvc.project_version_id AS pv_id
FROM component_vulnerabilities x
JOIN project_version_components pvc ON pvc.component_id = x.component_id
LEFT JOIN advisory a ON a.id = x.advisory_id
WHERE x.`+notMal,
		filterSpec{eq: map[string]string{"risk": "t.risk"}},
		riskOrder+", t.id", versionExtra("t.pv_id"), "pv_id")(w, r)
}

const riskOrder = `array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'], t.risk)`

func (s *Server) versionViolations(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler(withCur, `
SELECT v.id, v.rule_name, v.category, v.summary, v.severity, v.blocking, v.details, v.created_at, v.project_version_id AS pv_id,
  `+componentJSON("c")+` AS component
FROM curv v JOIN components c ON c.id = v.component_id`,
		filterSpec{eq: map[string]string{"category": "t.category", "rule": "t.rule_name", "severity": "t.severity"}},
		"t.created_at DESC, t.id", versionExtra("t.pv_id"), "pv_id")(w, r)
}

func (s *Server) versionScans(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `
SELECT s.id, s.trigger, s.violations_count AS violations, s.vulns_count AS vulns, s.status, s.created_at,
  s.project_version_id AS pv_id
FROM scans s`,
		filterSpec{eq: map[string]string{"status": "t.status", "trigger": "t.trigger"}, dateCol: "t.created_at"},
		"t.created_at DESC, t.id", versionExtra("t.pv_id"), "pv_id")(w, r)
}

func (s *Server) listComponents(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler(withCur, `
SELECT c.id, c.name, c.version, c.ecosystem, c.type, c.updated_at, g.direct, g.depth, g.dev,
  (SELECT count(DISTINCT v.project_id) FROM project_version_components pvc
     JOIN project_versions v ON v.id = pvc.project_version_id WHERE pvc.component_id = c.id) AS projects,
  (SELECT count(*) FROM curv WHERE curv.component_id = c.id) AS violations,
  (SELECT count(*) FROM component_vulnerabilities x WHERE x.component_id = c.id AND x.`+notMal+`) AS vulns
FROM components c
JOIN LATERAL (SELECT bool_or(direct) AS direct, min(depth) AS depth, bool_and(dev) AS dev
  FROM project_version_components pvc WHERE pvc.component_id = c.id HAVING count(*) > 0) g ON true`,
		filterSpec{ilike: map[string]string{"name": "t.name"}, eq: map[string]string{"version": "t.version", "ecosystem": "t.ecosystem"},
			dateCol: "t.updated_at", vulns: true, viols: true},
		"t.name, t.version, t.id", boolParam("direct", "t.direct"))(w, r)
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `
SELECT s.id, jsonb_build_object('id', p.id, 'name', p.name) AS project, v.name AS version, s.trigger,
  s.violations_count AS violations, s.vulns_count AS vulns, s.status, s.created_at, s.project_id
FROM scans s JOIN projects p ON p.id = s.project_id JOIN project_versions v ON v.id = s.project_version_id`,
		filterSpec{eq: map[string]string{"project_id": "t.project_id", "version": "t.version", "trigger": "t.trigger", "status": "t.status"},
			dateCol: "t.created_at", vulns: true, viols: true},
		"t.created_at DESC, t.id", nil, "project_id")(w, r)
}

// scanDetailSQL renders the full scan report.
var scanDetailSQL = `
SELECT jsonb_build_object('id', s.id, 'project', jsonb_build_object('id', p.id, 'name', p.name, 'source', p.source, 'url', p.url),
  'version', v.name, 'trigger', s.trigger, 'status', s.status, 'conclusion', s.conclusion, 'pr_number', s.pr_number,
  'head_sha', s.head_sha, 'created_at', s.created_at, 'finished_at', s.finished_at, 'error', s.error,
  'counts', jsonb_build_object('components', s.components_count, 'vulns', s.vulns_count, 'violations', s.violations_count,
     'malicious', s.malicious_count, 'suspicious', s.suspicious_count),
  'report_md', s.report_md,
  'findings', COALESCE((SELECT jsonb_agg(jsonb_build_object('rule', pv.rule_name, 'category', pv.category, 'severity', pv.severity,
      'blocking', pv.blocking, 'summary', pv.summary, 'component', ` + componentJSON("c") + `, 'details', pv.details)
      ORDER BY array_position(ARRAY['critical','high','medium','low','info'], pv.severity), pv.category, c.name)
    FROM policy_violations pv JOIN components c ON c.id = pv.component_id
    WHERE pv.scan_id = s.id AND pv.category IN ('suspicious', 'license')), '[]'::jsonb),
  'packages', COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'component', jsonb_build_object('id', c.id, 'name', c.name, 'version', c.version, 'ecosystem', c.ecosystem, 'purl', c.purl),
      'manifest_path', sp.manifest_path, 'change', sp.change, 'malware', sp.malware, 'vulnerable', sp.vulnerable,
      'risky_license', sp.risky_license, 'direct', sp.direct, 'depth', sp.depth, 'dev', sp.dev, 'via', sp.via,
      'paths', sp.paths, 'imported', sp.imported, 'licenses', c.licenses, 'graph_source', sp.graph_source,
      'vulns', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', x.advisory_id, 'summary', a.summary, 'risk', x.risk) ORDER BY x.advisory_id)
          FROM component_vulnerabilities x LEFT JOIN advisory a ON a.id = x.advisory_id WHERE x.component_id = c.id), '[]'::jsonb),
      'violations', COALESCE((SELECT jsonb_agg(jsonb_build_object('rule_name', pv.rule_name, 'category', pv.category, 'summary', pv.summary,
          'severity', pv.severity, 'blocking', pv.blocking) ORDER BY pv.rule_name)
          FROM policy_violations pv WHERE pv.scan_id = s.id AND pv.component_id = c.id), '[]'::jsonb)
    ) ORDER BY sp.malware DESC, sp.vulnerable DESC, c.name, c.version)
    FROM scan_packages sp JOIN components c ON c.id = sp.component_id WHERE sp.scan_id = s.id), '[]'::jsonb))
FROM scans s JOIN projects p ON p.id = s.project_id JOIN project_versions v ON v.id = s.project_version_id
WHERE s.id = $1`

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, scanDetailSQL, r.PathValue("id"))
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) listViolations(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler(withCur, `
SELECT v.id, v.rule_name, v.category, v.summary, v.severity, v.blocking, v.details, `+componentJSON("c")+` AS component,
  jsonb_build_object('id', p.id, 'name', p.name) AS project, pv.name AS version, v.scan_id, v.created_at,
  p.id AS project_id
FROM curv v JOIN components c ON c.id = v.component_id
JOIN projects p ON p.id = v.project_id JOIN project_versions pv ON pv.id = v.project_version_id`,
		filterSpec{eq: map[string]string{"rule": "t.rule_name", "category": "t.category", "project_id": "t.project_id", "version": "t.version",
			"severity": "t.severity"},
			dateCol: "t.created_at"},
		"t.created_at DESC, t.id", nil, "project_id")(w, r)
}
