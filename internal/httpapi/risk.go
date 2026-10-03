package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/license"
	"github.com/depguard/depguard/internal/render"
	"github.com/google/osv-scalibr/semantic"
	"github.com/jackc/pgx/v5"
	"github.com/safedep/vet/pkg/models"
)

// Risk analysis endpoints: attack paths, project license settings, license
// overview and the combined report. See docs/CONTRACTS.md "Risk analysis".

// ---------------------------------------------------------- advisories

type affectedRange struct {
	Eco    string `json:"eco"`
	Name   string `json:"name"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Fixed string `json:"fixed"`
		} `json:"events"`
	} `json:"ranges"`
}

// fixedIn is the lowest OSV "fixed" version above installed, "" if none.
func fixedIn(ecosystem, name, installed string, aff []affectedRange) string {
	eco := enrich.OSVEcosystem(&models.Package{Manifest: models.NewPackageManifestFromLocal("", ecosystem)})
	if eco == "" {
		return ""
	}
	norm := feeds.NormalizeName(eco, name)
	parse := func(v string) (semantic.Version, error) {
		if p, err := semantic.Parse(v, eco); err == nil {
			return p, nil
		}
		return semantic.Parse(v, "npm")
	}
	best := ""
	var bestV semantic.Version
	for _, a := range aff {
		if a.Eco != eco || a.Name != norm {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed == "" {
					continue
				}
				f, err := parse(e.Fixed)
				if err != nil {
					continue
				}
				if c, err := f.CompareStr(installed); err != nil || c <= 0 {
					continue
				}
				if best == "" {
					best, bestV = e.Fixed, f
				} else if c, err := bestV.CompareStr(e.Fixed); err == nil && c > 0 {
					best, bestV = e.Fixed, f
				}
			}
		}
	}
	return best
}

// loadAdvisories returns every advisory (incl. MAL-) of the components with
// EPSS/KEV (via CVE aliases) and the fixed version (stored fixed_in, else
// derived from OSV ranges), keyed by component id.
func loadAdvisories(ctx context.Context, tx pgx.Tx, compIDs []string) (map[string][]render.Vuln, error) {
	out := map[string][]render.Vuln{}
	if len(compIDs) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `
SELECT x.component_id, c.ecosystem, c.name, c.version, x.advisory_id, COALESCE(a.risk, x.risk), COALESCE(a.summary, ''),
  COALESCE(s.epss, 0), COALESCE(s.kev, false), COALESCE(x.fixed_in, ''),
  CASE WHEN x.fixed_in IS NULL THEN COALESCE((SELECT jsonb_agg(jsonb_build_object('eco', af.ecosystem, 'name', af.name_norm, 'ranges', af.ranges))
    FROM affected af WHERE af.advisory_id = x.advisory_id), '[]'::jsonb) ELSE '[]'::jsonb END
FROM component_vulnerabilities x JOIN components c ON c.id = x.component_id
LEFT JOIN advisory a ON a.id = x.advisory_id
LEFT JOIN LATERAL (SELECT max(epss)::float8 AS epss, bool_or(kev) AS kev FROM cve_score
  WHERE cve = ANY(ARRAY(SELECT x.advisory_id UNION SELECT alias FROM advisory_alias WHERE advisory_id = x.advisory_id))) s ON true
WHERE x.component_id = ANY($1)
ORDER BY x.component_id, array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW'], COALESCE(a.risk, x.risk)), x.advisory_id`, compIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var comp, eco, name, version string
		var v render.Vuln
		var raw []byte
		if err := rows.Scan(&comp, &eco, &name, &version, &v.ID, &v.Risk, &v.Summary, &v.EPSS, &v.KEV, &v.FixedIn, &raw); err != nil {
			return nil, err
		}
		// Stored by the engine (00004); computed from OSV ranges for rows scanned before it.
		var aff []affectedRange
		if v.FixedIn == "" && json.Unmarshal(raw, &aff) == nil {
			v.FixedIn = fixedIn(eco, name, version, aff)
		}
		out[comp] = append(out[comp], v)
	}
	return out, rows.Err()
}

// --------------------------------------------------- project version graph

type pathNode struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	Ecosystem    string  `json:"ecosystem"`
	Direct       *bool   `json:"direct"`
	Depth        *int    `json:"depth"`
	Vulns        int     `json:"vulns"`
	MaxRisk      *string `json:"max_risk"`
	Malware      bool    `json:"malware"`
	Suspicious   bool    `json:"suspicious"`
	LicenseIssue bool    `json:"license_issue"`

	dev      bool
	imported *bool
	advs     []render.Vuln
	suspSev  string
	suspText string
}

type pathEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type graphResp struct {
	Source    string            `json:"source"`
	Nodes     []*pathNode       `json:"nodes"`
	Edges     []pathEdge        `json:"edges"`
	Paths     []render.PathItem `json:"paths"`
	Truncated bool              `json:"truncated"`
}

const (
	maxGraphNodes   = 300
	maxPathsPerItem = 3
	maxPaths        = 300
)

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

// versionGraph computes attack paths of a project version from its stored
// dependency edges. target/advisory optionally restrict the targets.
func versionGraph(ctx context.Context, tx pgx.Tx, pvID, target, advisory string) (*graphResp, error) {
	var scanID *string
	if err := tx.QueryRow(ctx, withCur+`SELECT scan_id FROM cur WHERE pv_id = $1`, pvID).Scan(&scanID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
SELECT c.id, c.name, c.version, c.ecosystem, g.direct, g.depth, COALESCE(g.dev, false),
  (SELECT bool_or(sp.imported) FROM scan_packages sp WHERE sp.scan_id = $2 AND sp.component_id = c.id),
  EXISTS (SELECT 1 FROM policy_violations pv WHERE pv.scan_id = $2 AND pv.component_id = c.id AND pv.category = 'license'),
  COALESCE((SELECT jsonb_agg(jsonb_build_object('severity', pv.severity, 'summary', pv.summary))
    FROM policy_violations pv WHERE pv.scan_id = $2 AND pv.component_id = c.id AND pv.category = 'suspicious'), '[]'::jsonb)
FROM (SELECT component_id, bool_or(direct) AS direct, min(depth) AS depth, bool_and(dev) AS dev
      FROM project_version_components WHERE project_version_id = $1 GROUP BY component_id) g
JOIN components c ON c.id = g.component_id`, pvID, scanID)
	if err != nil {
		return nil, err
	}
	nodes := map[string]*pathNode{}
	var ids []string
	for rows.Next() {
		n := &pathNode{}
		var susp []byte
		if err := rows.Scan(&n.ID, &n.Name, &n.Version, &n.Ecosystem, &n.Direct, &n.Depth, &n.dev, &n.imported, &n.LicenseIssue, &susp); err != nil {
			rows.Close()
			return nil, err
		}
		var fs []struct{ Severity, Summary string }
		_ = json.Unmarshal(susp, &fs)
		for _, f := range fs {
			if !n.Suspicious || sevRank[f.Severity] < sevRank[n.suspSev] {
				n.suspSev, n.suspText = f.Severity, f.Summary
			}
			n.Suspicious = true
		}
		nodes[n.ID] = n
		ids = append(ids, n.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	advs, err := loadAdvisories(ctx, tx, ids)
	if err != nil {
		return nil, err
	}
	for id, vs := range advs {
		n := nodes[id]
		n.advs = vs
		for _, v := range vs {
			if strings.HasPrefix(v.ID, "MAL-") {
				n.Malware = true
				continue
			}
			n.Vulns++
			if n.MaxRisk == nil || riskRank(v.Risk) < riskRank(*n.MaxRisk) {
				r := v.Risk
				n.MaxRisk = &r
			}
		}
	}

	// parents[child] = parent ids ("" = the app).
	parents := map[string][]string{}
	depsdev := map[[2]string]bool{}
	nEdges, nDepsdev := 0, 0
	erows, err := tx.Query(ctx, `SELECT DISTINCT COALESCE(parent_component_id, ''), child_component_id, graph_source
		FROM project_version_dependencies WHERE project_version_id = $1`, pvID)
	if err != nil {
		return nil, err
	}
	for erows.Next() {
		var p, c, src string
		if err := erows.Scan(&p, &c, &src); err != nil {
			erows.Close()
			return nil, err
		}
		parents[c] = append(parents[c], p)
		nEdges++
		if src == "depsdev" {
			depsdev[[2]string{p, c}] = true
			nDepsdev++
		}
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return nil, err
	}
	ix := newPathIndex(parents)
	resp := &graphResp{Source: "lockfile", Nodes: []*pathNode{}, Edges: []pathEdge{}, Paths: []render.PathItem{}}
	switch {
	case nEdges == 0:
		resp.Source = "none"
	case nDepsdev == nEdges:
		resp.Source = "depsdev"
	}

	for _, id := range ids {
		n := nodes[id]
		if (n.Vulns == 0 && !n.Malware && !n.Suspicious) || (target != "" && id != target) {
			continue
		}
		if advisory != "" && !slices.ContainsFunc(n.advs, func(v render.Vuln) bool { return v.ID == advisory }) {
			continue
		}
		chains := ix.paths(id, maxPathsPerItem)
		approxAll := false
		if len(chains) == 0 { // no graph for this package: show it on its own
			chains, approxAll = [][]string{{id}}, n.Direct == nil || !*n.Direct
		}
		unknownDepth := approxAll // not in the graph and not known to be direct
		for _, ch := range chains {
			approx := approxAll
			chain := make([]render.PathNode, len(ch))
			for i, cid := range ch {
				cid := cid
				chain[i] = render.PathNode{Name: nodes[cid].Name, Version: nodes[cid].Version, ComponentID: &cid}
				parent := ""
				if i > 0 {
					parent = ch[i-1]
				}
				approx = approx || depsdev[[2]string{parent, cid}]
			}
			item := render.NewPath(chain, slices.Clone(n.advs), n.imported, n.dev, approx, n.suspSev, n.suspText)
			if unknownDepth {
				item.Depth = 0
			}
			resp.Paths = append(resp.Paths, item)
		}
	}
	render.SortPaths(resp.Paths)
	if len(resp.Paths) > maxPaths {
		resp.Paths, resp.Truncated = resp.Paths[:maxPaths], true
	}

	// Only the subgraph on the returned paths, capped for the UI.
	inGraph := map[string]bool{}
	seenEdge := map[pathEdge]bool{}
	for _, p := range resp.Paths {
		var add []string
		for _, c := range p.Chain {
			if !inGraph[*c.ComponentID] {
				add = append(add, *c.ComponentID)
			}
		}
		if len(inGraph)+len(add) > maxGraphNodes {
			resp.Truncated = true
			continue
		}
		for _, id := range add {
			inGraph[id] = true
			resp.Nodes = append(resp.Nodes, nodes[id])
		}
		from := "app"
		for _, c := range p.Chain {
			e := pathEdge{from, *c.ComponentID}
			if !seenEdge[e] {
				seenEdge[e] = true
				resp.Edges = append(resp.Edges, e)
			}
			from = *c.ComponentID
		}
	}
	return resp, nil
}

func riskRank(r string) int {
	if i := slices.Index([]string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}, r); i >= 0 {
		return i
	}
	return 4
}

// pathIndex answers "chains from the app to X" for a whole version: one
// breadth-first pass from the app gives every node's distance; each target's
// chains are then read back along parents that are reachable from the app,
// nearest first, so unreachable parts of the graph are never explored.
type pathIndex struct {
	parents map[string][]string // child -> parents ("" = the app), nearest first
	dist    map[string]int
}

func newPathIndex(parents map[string][]string) *pathIndex {
	children := map[string][]string{}
	for c, ps := range parents {
		for _, p := range ps {
			children[p] = append(children[p], c)
		}
	}
	dist := map[string]int{"": 0}
	queue := []string{""}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, c := range children[n] {
			if _, seen := dist[c]; !seen {
				dist[c] = dist[n] + 1
				queue = append(queue, c)
			}
		}
	}
	sorted := make(map[string][]string, len(parents))
	for c, ps := range parents {
		var r []string
		for _, p := range ps {
			if _, ok := dist[p]; ok {
				r = append(r, p)
			}
		}
		slices.SortFunc(r, func(a, b string) int {
			if dist[a] != dist[b] {
				return dist[a] - dist[b]
			}
			return strings.Compare(a, b)
		})
		sorted[c] = slices.Compact(r)
	}
	return &pathIndex{parents: sorted, dist: dist}
}

// paths returns up to k distinct chains app→…→target (component ids, the
// direct dependency first), shortest first and at most two links longer than
// the shortest; nil when target is not reachable from the app.
func (ix *pathIndex) paths(target string, k int) [][]string {
	d, ok := ix.dist[target]
	if !ok || target == "" {
		return nil
	}
	limit, steps := d+2, 0
	var out [][]string
	var walk func(node string, suffix []string)
	walk = func(node string, suffix []string) {
		if steps++; len(out) >= 4*k || steps > 4000 {
			return
		}
		if node == "" {
			ch := slices.Clone(suffix)
			slices.Reverse(ch)
			out = append(out, ch)
			return
		}
		if len(suffix)+ix.dist[node] >= limit+1 {
			return // cannot reach the app within the length limit
		}
		next := append(slices.Clone(suffix), node)
		for _, p := range ix.parents[node] {
			if p == "" || !slices.Contains(next, p) {
				walk(p, next)
			}
		}
	}
	walk(target, nil)
	slices.SortStableFunc(out, func(a, b []string) int { return len(a) - len(b) })
	if len(out) > k {
		out = out[:k]
	}
	return out
}

// checkVersion 404s unless version vid belongs to project id.
func checkVersion(ctx context.Context, tx pgx.Tx, id, vid string) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM project_versions WHERE id = $1 AND project_id = $2)`, vid, id).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return errNotFound
	}
	return nil
}

func (s *Server) versionPaths(w http.ResponseWriter, r *http.Request) error {
	var out *graphResp
	err := s.tx(r, func(tx pgx.Tx) error {
		if err := checkVersion(r.Context(), tx, r.PathValue("id"), r.PathValue("vid")); err != nil {
			return err
		}
		var err error
		out, err = versionGraph(r.Context(), tx, r.PathValue("vid"), r.URL.Query().Get("target"), r.URL.Query().Get("advisory"))
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) vulnPaths(w http.ResponseWriter, r *http.Request) error {
	type item struct {
		Project struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"project"`
		Version   string            `json:"version"`
		VersionID string            `json:"version_id"`
		Paths     []render.PathItem `json:"paths"`
	}
	items := []item{}
	err := s.tx(r, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
SELECT DISTINCT p.id, p.name, v.id, v.name FROM component_vulnerabilities x
JOIN project_version_components pvc ON pvc.component_id = x.component_id
JOIN project_versions v ON v.id = pvc.project_version_id JOIN projects p ON p.id = v.project_id
WHERE x.advisory_id = $1 ORDER BY p.name, v.name LIMIT 50`, r.PathValue("id"))
		if err != nil {
			return err
		}
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.Project.ID, &it.Project.Name, &it.VersionID, &it.Version); err != nil {
				rows.Close()
				return err
			}
			items = append(items, it)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i := range items {
			g, err := versionGraph(r.Context(), tx, items[i].VersionID, "", r.PathValue("id"))
			if err != nil {
				return err
			}
			items[i].Paths = g.Paths
		}
		return nil
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// -------------------------------------------------------- scan report

// loadReport builds the render.Report of a stored scan.
func loadReport(ctx context.Context, tx pgx.Tx, scanID, publicURL string) (render.Report, error) {
	r := render.Report{PublicURL: publicURL, ScanID: scanID}
	var created time.Time
	var license, source *string
	err := tx.QueryRow(ctx, `SELECT p.name, p.license, p.license_source, p.usage_model, v.name, s.created_at
		FROM scans s JOIN projects p ON p.id = s.project_id JOIN project_versions v ON v.id = s.project_version_id
		WHERE s.id = $1`, scanID).Scan(&r.Project.Name, &license, &source, &r.Project.UsageModel, &r.Version, &created)
	if err != nil {
		return r, err
	}
	r.Project.License, r.Project.LicenseSource = deref(license), deref(source)
	r.Date = created.UTC().Format("2006-01-02 15:04 UTC")

	rows, err := tx.Query(ctx, `
SELECT c.id, c.name, c.version, c.ecosystem, sp.manifest_path, sp.malware, sp.vulnerable, sp.risky_license,
  sp.direct, COALESCE(sp.depth, 0), COALESCE(sp.dev, false), sp.via, sp.paths, sp.imported, COALESCE(sp.graph_source, ''), c.licenses
FROM scan_packages sp JOIN components c ON c.id = sp.component_id WHERE sp.scan_id = $1
ORDER BY sp.malware DESC, sp.vulnerable DESC, sp.manifest_path, c.name, c.version`, scanID)
	if err != nil {
		return r, err
	}
	var ids []string
	byID := map[string][]int{}
	for rows.Next() {
		var p render.Package
		var paths []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Version, &p.Ecosystem, &p.ManifestPath, &p.Malware, &p.Vulnerable, &p.RiskyLicense,
			&p.Direct, &p.Depth, &p.Dev, &p.Via, &paths, &p.Imported, &p.GraphSource, &p.Licenses); err != nil {
			rows.Close()
			return r, err
		}
		_ = json.Unmarshal(paths, &p.Paths)
		if _, ok := byID[p.ID]; !ok {
			ids = append(ids, p.ID)
		}
		byID[p.ID] = append(byID[p.ID], len(r.Packages))
		r.Packages = append(r.Packages, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return r, err
	}
	advs, err := loadAdvisories(ctx, tx, ids)
	if err != nil {
		return r, err
	}
	for id, idx := range byID {
		for _, i := range idx {
			r.Packages[i].Vulns = advs[id]
		}
	}
	vrows, err := tx.Query(ctx, `SELECT component_id, rule_name, category, summary, severity, blocking, details
		FROM policy_violations WHERE scan_id = $1 ORDER BY created_at, id`, scanID)
	if err != nil {
		return r, err
	}
	defer vrows.Close()
	for vrows.Next() {
		var comp, rule, cat, summary, sev string
		var blocking bool
		var details map[string]any
		if err := vrows.Scan(&comp, &rule, &cat, &summary, &sev, &blocking, &details); err != nil {
			return r, err
		}
		var pkg render.Package
		if idx := byID[comp]; len(idx) > 0 {
			pkg = r.Packages[idx[0]]
		}
		if cat == "suspicious" || cat == "license" {
			r.Findings = append(r.Findings, render.Finding{Rule: rule, Category: cat, Severity: sev, Blocking: blocking,
				Summary: summary, Package: pkg.Name + "@" + pkg.Version, ManifestPath: pkg.ManifestPath, Details: details})
			continue
		}
		var top []render.Vuln
		for _, v := range pkg.Vulns {
			if (cat == "malware") == strings.HasPrefix(v.ID, "MAL-") && (cat == "malware" || cat == "vulnerability") && len(top) < 3 {
				top = append(top, render.Vuln{ID: v.ID, Risk: v.Risk})
			}
		}
		r.Violations = append(r.Violations, render.Violation{Rule: rule, Category: cat, Summary: summary, Package: pkg, Vulns: top})
	}
	return r, vrows.Err()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Server) scanPaths(w http.ResponseWriter, r *http.Request) error {
	var rep render.Report
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		rep, err = loadReport(r.Context(), tx, r.PathValue("id"), s.d.PublicURL)
		return err
	})
	if err != nil {
		return err
	}
	paths := render.Paths(rep)
	if paths == nil {
		paths = []render.PathItem{}
	}
	return writeJSON(w, http.StatusOK, map[string]any{"paths": paths})
}

var reportTypes = map[string][2]string{
	"md":   {"text/markdown; charset=utf-8", "md"},
	"json": {"application/json", "json"},
	"html": {"text/html; charset=utf-8", "html"},
}

// scanReport serves the combined report (web: service JWT; machine: API key).
func (s *Server) scanReport(w http.ResponseWriter, r *http.Request) error {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "md"
	}
	t, ok := reportTypes[format]
	if !ok {
		return badRequest("format must be md, json or html")
	}
	var rep render.Report
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		rep, err = loadReport(r.Context(), tx, r.PathValue("id"), s.d.PublicURL)
		return err
	})
	if err != nil {
		return err
	}
	out, err := render.Full(rep, format)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", t[0])
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="depguard-report-%s.%s"`, safeFilename(rep.ScanID), t[1]))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if format == "html" {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	}
	_, err = w.Write([]byte(out))
	return err
}

var unsafeFile = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func safeFilename(s string) string { return unsafeFile.ReplaceAllString(s, "_") }

// ------------------------------------------------- project settings

var usageModels = map[string]bool{"internal": true, "saas": true, "distributed_binary": true, "distributed_source": true}

// spdxish accepts SPDX ids/expressions incl. LicenseRef-, AND/OR/WITH and parentheses.
var spdxish = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+:\-]*( +(AND|OR|WITH|and|or|with) +\(*[A-Za-z0-9][A-Za-z0-9.+:\-]*\)*)*$`)

func validLicense(l string) bool {
	l = strings.TrimSpace(l)
	stripped := strings.NewReplacer("(", "", ")", "").Replace(l)
	return len(l) <= 200 && strings.Count(l, "(") == strings.Count(l, ")") && spdxish.MatchString(stripped)
}

func (s *Server) getProjectSettings(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `SELECT jsonb_build_object('license', license, 'license_source', license_source,
			'detected_license', CASE WHEN license_source = 'override' THEN NULL ELSE license END, 'usage_model', usage_model)
			FROM projects WHERE id = $1`, r.PathValue("id"))
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) putProjectSettings(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		License    json.RawMessage `json:"license"` // absent = keep, null = clear override, string = override
		UsageModel string          `json:"usage_model"`
		// Read-only fields are accepted (the web may send the whole object) and ignored.
		LicenseSource   *string `json:"license_source"`
		DetectedLicense *string `json:"detected_license"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if body.UsageModel != "" && !usageModels[body.UsageModel] {
		return badRequest("usage_model must be internal, saas, distributed_binary or distributed_source")
	}
	var lic *string
	setLic, clearLic := false, false
	if len(body.License) > 0 {
		if string(body.License) == "null" {
			clearLic = true
		} else if err := json.Unmarshal(body.License, &lic); err != nil || lic == nil {
			return badRequest("license must be an SPDX expression or null")
		} else if v := strings.TrimSpace(*lic); v == "" {
			clearLic = true
		} else if !validLicense(v) {
			return badRequest("license must be an SPDX expression such as MIT or Apache-2.0 OR MIT")
		} else {
			lic, setLic = &v, true
		}
	}
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE projects SET
			usage_model = COALESCE(NULLIF($2, ''), usage_model),
			license = CASE WHEN $3 THEN $4 WHEN $5 AND license_source = 'override' THEN NULL ELSE license END,
			license_source = CASE WHEN $3 THEN 'override' WHEN $5 AND license_source = 'override' THEN NULL ELSE license_source END,
			updated_at = now()
			WHERE id = $1`, r.PathValue("id"), body.UsageModel, setLic, lic, clearLic)
		if err == nil && tag.RowsAffected() == 0 {
			return errNotFound
		}
		return err
	})
	if err != nil {
		return err
	}
	return s.getProjectSettings(w, r)
}

// ---------------------------------------------------------- licenses

func (s *Server) versionLicenses(w http.ResponseWriter, r *http.Request) error {
	type dist struct {
		License  string `json:"license"`
		Count    int    `json:"count"`
		Category string `json:"category"` // license.Explain categories
		Summary  string `json:"summary"`
	}
	out := map[string]any{}
	err := s.tx(r, func(tx pgx.Tx) error {
		ctx, vid := r.Context(), r.PathValue("vid")
		var lic, src *string
		var usage string
		err := tx.QueryRow(ctx, `SELECT p.license, p.license_source, p.usage_model FROM projects p
			JOIN project_versions v ON v.project_id = p.id WHERE v.id = $1 AND p.id = $2`, vid, r.PathValue("id")).Scan(&lic, &src, &usage)
		if err != nil {
			return err
		}
		out["project_license"], out["license_source"], out["usage_model"] = lic, src, usage
		findings, err := one(ctx, tx, withCur+`SELECT COALESCE(jsonb_agg(jsonb_build_object('id', v.id, 'rule', v.rule_name,
			'severity', v.severity, 'blocking', v.blocking, 'summary', v.summary, 'component', `+componentJSON("c")+`, 'details', v.details)
			ORDER BY array_position(ARRAY['critical','high','medium','low','info'], v.severity), c.name), '[]'::jsonb)
			FROM curv v JOIN components c ON c.id = v.component_id WHERE v.project_version_id = $1 AND v.category = 'license'`, vid)
		if err != nil {
			return err
		}
		out["findings"] = findings
		rows, err := tx.Query(ctx, `SELECT COALESCE(l, 'UNKNOWN'), count(DISTINCT c.id)
			FROM (SELECT DISTINCT component_id FROM project_version_components WHERE project_version_id = $1) pvc
			JOIN components c ON c.id = pvc.component_id LEFT JOIN LATERAL unnest(c.licenses) l ON true
			GROUP BY 1 ORDER BY 2 DESC, 1`, vid)
		if err != nil {
			return err
		}
		ds, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (dist, error) {
			var d dist
			err := row.Scan(&d.License, &d.Count)
			d.Category, d.Summary = license.Explain(d.License)
			return d, err
		})
		if ds == nil {
			ds = []dist{}
		}
		out["distribution"] = ds
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------- shared filters

// boolParam adds "col = value" for ?name=true|false.
func boolParam(name, col string) func(*http.Request, *where) error {
	return func(r *http.Request, w *where) error {
		switch v := r.URL.Query().Get(name); v {
		case "true", "false":
			w.add(col+" = ?", v == "true")
		case "":
		default:
			return badRequest("%s must be true or false", name)
		}
		return nil
	}
}

// extras chains list filter functions.
func extras(fs ...func(*http.Request, *where) error) func(*http.Request, *where) error {
	return func(r *http.Request, w *where) error {
		for _, f := range fs {
			if err := f(r, w); err != nil {
				return err
			}
		}
		return nil
	}
}
