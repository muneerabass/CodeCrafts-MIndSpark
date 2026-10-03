package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/depguard/depguard/internal/pkgrules"
	"github.com/depguard/depguard/internal/scan"
	"github.com/jackc/pgx/v5"
	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

// ------------------------------------------------------------ dashboard

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) error {
	days := map[string]int{"7d": 7, "30d": 30, "90d": 90, "": 30}[r.URL.Query().Get("range")]
	if days == 0 {
		return badRequest("range must be 7d, 30d or 90d")
	}
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, withCur+`,
inv AS (SELECT DISTINCT component_id FROM project_version_components),
latest AS (SELECT DISTINCT ON (component_id) component_id, status FROM package_analyses ORDER BY component_id, created_at DESC),
days AS (SELECT generate_series(current_date - ($1::int - 1), current_date, interval '1 day')::date AS d),
pvd AS (SELECT created_at::date AS d, count(*) AS n FROM policy_violations WHERE created_at >= current_date - ($1::int - 1) GROUP BY 1),
vd AS (SELECT first_seen::date AS d,
         count(*) FILTER (WHERE risk = 'CRITICAL') AS critical, count(*) FILTER (WHERE risk = 'HIGH') AS high,
         count(*) FILTER (WHERE risk = 'MEDIUM') AS medium, count(*) FILTER (WHERE risk = 'LOW') AS low
       FROM component_vulnerabilities WHERE first_seen >= current_date - ($1::int - 1) AND `+notMal+` GROUP BY 1),
pvul AS (SELECT v.project_id, count(DISTINCT (x.component_id, x.advisory_id)) AS vulns
       FROM component_vulnerabilities x JOIN project_version_components pvc ON pvc.component_id = x.component_id
       JOIN project_versions v ON v.id = pvc.project_version_id WHERE x.`+notMal+` GROUP BY v.project_id)
SELECT jsonb_build_object(
  'projects', (SELECT count(*) FROM projects),
  'components', (SELECT count(*) FROM inv),
  'suspicious', (SELECT count(*) FROM latest JOIN inv USING (component_id) WHERE latest.status = 'suspicious'),
  'malicious', (SELECT count(*) FROM inv WHERE
      EXISTS (SELECT 1 FROM latest l WHERE l.component_id = inv.component_id AND l.status = 'malicious')
      OR EXISTS (SELECT 1 FROM component_vulnerabilities x WHERE x.component_id = inv.component_id AND x.advisory_id LIKE 'MAL-%')),
  'violations', (SELECT count(*) FROM curv),
  'vulnerabilities', (SELECT count(DISTINCT x.advisory_id) FROM component_vulnerabilities x JOIN inv USING (component_id) WHERE x.`+notMal+`),
  'transitive_vulnerabilities', (SELECT count(DISTINCT (x.component_id, x.advisory_id)) FROM component_vulnerabilities x
      WHERE x.`+notMal+` AND EXISTS (SELECT 1 FROM project_version_components pvc WHERE pvc.component_id = x.component_id AND pvc.direct = false)),
  'attack_paths', (SELECT count(*) FROM (SELECT DISTINCT pvc.project_version_id, pvc.component_id FROM project_version_components pvc
      WHERE EXISTS (SELECT 1 FROM component_vulnerabilities x WHERE x.component_id = pvc.component_id)
         OR EXISTS (SELECT 1 FROM curv WHERE curv.component_id = pvc.component_id
                    AND curv.project_version_id = pvc.project_version_id AND curv.category = 'suspicious')) z),
  'suspicious_findings', (SELECT count(*) FROM curv WHERE category = 'suspicious'),
  'license_issues', (SELECT count(*) FROM curv WHERE category = 'license'),
  'violations_over_time', (SELECT jsonb_agg(jsonb_build_object('date', days.d, 'count', COALESCE(pvd.n, 0)) ORDER BY days.d)
      FROM days LEFT JOIN pvd USING (d)),
  'violations_by_check', COALESCE((SELECT jsonb_agg(jsonb_build_object('check', category, 'count', n) ORDER BY n DESC, category)
      FROM (SELECT category, count(*) AS n FROM curv GROUP BY category) z), '[]'::jsonb),
  'vulns_over_time', (SELECT jsonb_agg(jsonb_build_object('date', days.d, 'critical', COALESCE(vd.critical, 0),
      'high', COALESCE(vd.high, 0), 'medium', COALESCE(vd.medium, 0), 'low', COALESCE(vd.low, 0)) ORDER BY days.d)
      FROM days LEFT JOIN vd USING (d)),
  'top_projects', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', p.id, 'name', p.name, 'vulns', pvul.vulns) ORDER BY pvul.vulns DESC, p.name)
      FROM (SELECT * FROM pvul ORDER BY vulns DESC LIMIT 5) pvul JOIN projects p ON p.id = pvul.project_id), '[]'::jsonb))`, days)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// ------------------------------------------------------- package analyses

const analysisInner = `
SELECT a.id, ` + `jsonb_build_object('id', c.id, 'name', c.name, 'version', c.version, 'ecosystem', c.ecosystem)` + ` AS component,
  CASE WHEN p.id IS NULL THEN NULL ELSE jsonb_build_object('id', p.id, 'name', p.name) END AS project,
  pv.name AS version, a.status, a.verified, a.created_at, p.id AS project_id,
  a.source, a.evidence, a.verified_by, a.verified_at, a.scan_id
FROM package_analyses a JOIN components c ON c.id = a.component_id
LEFT JOIN project_versions pv ON pv.id = a.project_version_id LEFT JOIN projects p ON p.id = pv.project_id`

func (s *Server) listAnalyses(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", analysisInner,
		filterSpec{eq: map[string]string{"project_id": "t.project_id", "version": "t.version", "status": "t.status"}, dateCol: "t.created_at"},
		"t.created_at DESC, t.id", func(r *http.Request, w *where) error {
			switch v := r.URL.Query().Get("verified"); v {
			case "true", "false":
				w.add("t.verified = ?", v == "true")
			case "":
			default:
				return badRequest("verified must be true or false")
			}
			return nil
		}, "project_id", "source", "evidence", "verified_by", "verified_at", "scan_id")(w, r)
}

func (s *Server) getAnalysis(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `SELECT to_jsonb(t) - 'project_id' FROM (`+analysisInner+`) t WHERE t.id = $1`, r.PathValue("id"))
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) verifyAnalysis(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Status string `json:"status"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if body.Status != "malicious" && body.Status != "clean" {
		return badRequest("status must be malicious or clean")
	}
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE package_analyses SET
			source = CASE WHEN status <> $2 THEN 'admin' ELSE source END,
			status = $2, verified = true, verified_by = $3, verified_at = now() WHERE id = $1`,
			r.PathValue("id"), body.Status, principal(r).UserID)
		if err == nil && tag.RowsAffected() == 0 {
			return errNotFound
		}
		return err
	})
	if err != nil {
		return err
	}
	return s.getAnalysis(w, r)
}

// -------------------------------------------------------- vulnerabilities

func (s *Server) listVulns(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `
SELECT x.advisory_id AS id, a.summary, COALESCE(a.risk, (array_agg(x.risk))[1]) AS risk,
  count(DISTINCT x.component_id) AS affected_components, count(DISTINCT v.project_id) AS affected_projects,
  a.published, a.modified
FROM component_vulnerabilities x LEFT JOIN advisory a ON a.id = x.advisory_id
LEFT JOIN project_version_components pvc ON pvc.component_id = x.component_id
LEFT JOIN project_versions v ON v.id = pvc.project_version_id
WHERE x.`+notMal+`
GROUP BY x.advisory_id, a.summary, a.risk, a.published, a.modified`,
		filterSpec{eq: map[string]string{"risk": "t.risk"}, ilike: map[string]string{"id": "t.id"}, dateCol: "t.published"},
		riskOrder+", t.published DESC NULLS LAST, t.id", nil)(w, r)
}

func (s *Server) getVuln(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `
WITH ids AS (SELECT $1::text AS id UNION SELECT alias FROM advisory_alias WHERE advisory_id = $1)
SELECT jsonb_build_object('id', a.id, 'summary', a.summary, 'details', a.details, 'risk', a.risk,
  'aliases', COALESCE((SELECT jsonb_agg(alias ORDER BY alias) FROM advisory_alias WHERE advisory_id = a.id), '[]'::jsonb),
  'severity', a.severity, 'published', a.published, 'modified', a.modified,
  'references', COALESCE(a.raw->'references', '[]'::jsonb),
  'epss', (SELECT max(epss) FROM cve_score WHERE cve IN (SELECT id FROM ids)),
  'kev', COALESCE((SELECT bool_or(kev) FROM cve_score WHERE cve IN (SELECT id FROM ids)), false))
FROM advisory a WHERE a.id = $1`, r.PathValue("id"))
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) vulnComponents(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `
SELECT `+componentJSON("c")+` AS component, c.name, c.version, x.advisory_id,
  COALESCE((SELECT jsonb_agg(DISTINCT jsonb_build_object('id', p.id, 'name', p.name))
    FROM project_version_components pvc JOIN project_versions v ON v.id = pvc.project_version_id
    JOIN projects p ON p.id = v.project_id WHERE pvc.component_id = c.id), '[]'::jsonb) AS projects
FROM component_vulnerabilities x JOIN components c ON c.id = x.component_id`,
		filterSpec{}, "t.name, t.version", func(r *http.Request, w *where) error {
			w.add("t.advisory_id = ?", r.PathValue("id"))
			return nil
		}, "name", "version", "advisory_id")(w, r)
}

// ----------------------------------------------------------------- policy

// PolicyDoc is tenant_settings.policy.
type PolicyDoc struct {
	Presets struct {
		Vulnerability struct {
			MinRisk string `json:"min_risk"`
		} `json:"vulnerability"`
		Malware struct {
			Enabled bool `json:"enabled"`
		} `json:"malware"`
		License    scan.LicensePreset    `json:"license"`
		Suspicious scan.SuspiciousPreset `json:"suspicious"`
		Popularity struct {
			Enabled  bool `json:"enabled"`
			MinStars int  `json:"min_stars"`
		} `json:"popularity"`
		Maintenance struct {
			Enabled      bool    `json:"enabled"`
			MinScorecard float64 `json:"min_scorecard"`
		} `json:"maintenance"`
		Packages []scan.PackageRule `json:"packages"`
	} `json:"presets"`
	Custom []CustomRule `json:"custom"`
}

// CustomRule is an advanced CEL rule.
type CustomRule struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Summary  string `json:"summary"`
	Expr     string `json:"expr"`
}

// DefaultPolicy mirrors scan.DefaultRules: malware, critical/high vulns; license and suspicious presets on.
func DefaultPolicy() PolicyDoc {
	var p PolicyDoc
	p.Presets.Vulnerability.MinRisk = "HIGH"
	p.Presets.Malware.Enabled = true
	// License risk comes from internal/license rules; a default deny list would double-report.
	p.Presets.License = scan.LicensePreset{Deny: []string{}, Enabled: true, BlockingSeverity: scan.SeverityHigh}
	p.Presets.Suspicious = scan.DefaultSuspicious()
	p.Presets.Popularity.MinStars = 10
	p.Presets.Maintenance.MinScorecard = 3
	p.Custom = []CustomRule{}
	return p
}

var suspiciousRules = map[string]bool{"typosquat": true, "unmaintained": true, "deprecated": true, "new-package": true,
	"no-source-repo": true, "unusual-behaviour": true}

var categories = map[string]checks.CheckType{
	"vulnerability": checks.CheckType_CheckTypeVulnerability,
	"malware":       checks.CheckType_CheckTypeMalware,
	"license":       checks.CheckType_CheckTypeLicense,
	"popularity":    checks.CheckType_CheckTypePopularity,
	"maintenance":   checks.CheckType_CheckTypeMaintenance,
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) error {
	p := DefaultPolicy()
	err := s.tx(r, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(r.Context(), `SELECT policy FROM tenant_settings`).Scan(&raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &p)
	})
	if err != nil {
		return err
	}
	if p.Custom == nil {
		p.Custom = []CustomRule{}
	}
	return writeJSON(w, http.StatusOK, p)
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) error {
	p := DefaultPolicy()
	if err := decode(w, r, jsonLimit, &p); err != nil {
		return err
	}
	switch p.Presets.Vulnerability.MinRisk {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "OFF":
	default:
		return badRequest("presets.vulnerability.min_risk must be CRITICAL, HIGH, MEDIUM, LOW or OFF")
	}
	if p.Presets.Popularity.MinStars < 0 || p.Presets.Maintenance.MinScorecard < 0 || p.Presets.Maintenance.MinScorecard > 10 {
		return badRequest("invalid preset thresholds")
	}
	switch p.Presets.License.BlockingSeverity {
	case "critical", "high", "medium", "low", "info":
	default:
		return badRequest("presets.license.blocking_severity must be critical, high, medium, low or info")
	}
	if m := p.Presets.Suspicious.UnmaintainedMonths; m < 1 || m > 240 {
		return badRequest("presets.suspicious.unmaintained_months must be between 1 and 240")
	}
	if p.Presets.Suspicious.Blocking == nil {
		p.Presets.Suspicious.Blocking = []string{}
	}
	for _, b := range p.Presets.Suspicious.Blocking {
		if !suspiciousRules[b] {
			return badRequest("presets.suspicious.blocking: unknown rule %q", b)
		}
	}
	if err := pkgrules.Validate(p.Presets.Packages); err != nil {
		return badRequest("presets.packages: %v", err)
	}
	if len(p.Custom) > 100 {
		return badRequest("at most 100 custom rules")
	}
	seen := map[string]bool{}
	rules := make([]scan.Rule, 0, len(p.Custom))
	for _, c := range p.Custom {
		cat, ok := categories[c.Category]
		if c.Name == "" || seen[c.Name] || !ok || strings.TrimSpace(c.Expr) == "" {
			return badRequest("custom rule %q: name must be unique and non-empty, category one of vulnerability|malware|license|popularity|maintenance, expr required", c.Name)
		}
		seen[c.Name] = true
		rules = append(rules, scan.Rule{Name: c.Name, Category: cat, Summary: c.Summary, Expr: c.Expr})
	}
	if _, err := scan.NewPolicy(rules); err != nil {
		return badRequest("invalid CEL: %v", err)
	}
	raw, _ := json.Marshal(p)
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE tenant_settings SET policy = $1, updated_at = now()`, raw)
		if err == nil && tag.RowsAffected() == 0 {
			return errf(http.StatusNotFound, "tenant not provisioned")
		}
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, p)
}

// testPolicy evaluates one CEL expression against a package whose insights are
// rebuilt from stored data (empty when the package is unknown to the tenant).
func (s *Server) testPolicy(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Expr      string `json:"expr"`
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Version   string `json:"version"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if body.Expr == "" || body.Name == "" || body.Ecosystem == "" {
		return badRequest("expr, ecosystem and name are required")
	}
	pol, err := scan.NewPolicy([]scan.Rule{{Name: "test", Category: checks.CheckType_CheckTypeOther, Expr: body.Expr}})
	if err != nil {
		return writeJSON(w, http.StatusOK, map[string]any{"matched": false, "error": err.Error()})
	}
	ins := map[string]any{"vulnerabilities": []any{}, "licenses": []string{}}
	err = s.tx(r, func(tx pgx.Tx) error {
		var compID string
		var licenses []string
		err := tx.QueryRow(r.Context(), `SELECT id, licenses FROM components WHERE ecosystem = $1 AND name = $2 AND version = $3
			ORDER BY updated_at DESC LIMIT 1`, body.Ecosystem, body.Name, body.Version).Scan(&compID, &licenses)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		ins["licenses"] = licenses
		rows, err := tx.Query(r.Context(), `SELECT x.advisory_id, COALESCE(a.summary, ''), COALESCE(a.risk, x.risk),
			COALESCE((SELECT array_agg(alias) FROM advisory_alias WHERE advisory_id = x.advisory_id), '{}')
			FROM component_vulnerabilities x LEFT JOIN advisory a ON a.id = x.advisory_id WHERE x.component_id = $1`, compID)
		if err != nil {
			return err
		}
		var vulns []any
		for rows.Next() {
			var id, summary, risk string
			var aliases []string
			if err := rows.Scan(&id, &summary, &risk, &aliases); err != nil {
				return err
			}
			v := map[string]any{"id": id, "summary": summary, "aliases": aliases}
			if risk != "UNKNOWN" {
				v["severities"] = []any{map[string]string{"type": "CVSS_V3", "risk": risk}}
			}
			vulns = append(vulns, v)
		}
		if vulns != nil {
			ins["vulnerabilities"] = vulns
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	pkg := &models.Package{Manifest: models.NewPackageManifestFromLocal("policy-test", body.Ecosystem)}
	pkg.Name, pkg.Version = body.Name, body.Version
	pkg.Insights = &insightapi.PackageVersionInsight{}
	raw, _ := json.Marshal(ins)
	if err := json.Unmarshal(raw, pkg.Insights); err != nil {
		return err
	}
	vs, err := pol.Evaluate(pkg)
	if err != nil {
		return writeJSON(w, http.StatusOK, map[string]any{"matched": false, "error": err.Error()})
	}
	return writeJSON(w, http.StatusOK, map[string]any{"matched": len(vs) > 0})
}
