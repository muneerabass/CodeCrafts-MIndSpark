package engine

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/render"
	"github.com/depguard/depguard/internal/scan"
	"github.com/jackc/pgx/v5"
	"github.com/safedep/vet/pkg/models"
)

// finding is one evaluated package (PR: added/changed; full scan: all).
type finding struct {
	pkg         *models.Package
	path        string
	change      string // full | added | changed
	vulns       []scan.Vuln
	violations  []scan.Violation
	malware     bool
	vulnerable  bool
	risky       bool
	componentID string

	// Dependency-graph context (nil/0 = unknown).
	direct, dev, imported *bool
	depth                 int
	via                   []string
	paths                 [][]string
	graphSource           string
	approximate           bool
	// checks are findings from risk checkers (suspicious, license).
	checks []scan.Finding
}

func (f *finding) ecosystem() string { return f.pkg.Manifest.Ecosystem }

// evaluate enriches packages, applies the tenant policy and exclusions,
// fills graph context from rc and runs the risk checkers.
func (d Deps) evaluate(ctx context.Context, changes []scan.Change, st settings, rc *riskCtx) ([]*finding, error) {
	if len(changes) == 0 {
		return nil, nil
	}
	pkgs := make([]*models.Package, len(changes))
	for i, c := range changes {
		pkgs[i] = c.Package
	}
	if d.Enricher != nil {
		if err := d.Enricher.Enrich(ctx, pkgs); err != nil {
			return nil, fmt.Errorf("enrich: %w", err)
		}
	}
	pol, err := scan.NewPolicy(st.Rules)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]*finding, 0, len(changes))
	for _, c := range changes {
		vs, err := pol.Evaluate(c.Package)
		if err != nil {
			return nil, err
		}
		f := &finding{pkg: c.Package, path: c.Path, change: c.Kind, vulns: scan.Vulns(c.Package),
			violations: scan.ApplyExclusions(vs, st.Exclusions, now), malware: scan.IsMalicious(c.Package)}
		for _, v := range f.vulns {
			if !strings.HasPrefix(v.ID, "MAL-") {
				f.vulnerable = true
			}
		}
		for _, v := range f.violations {
			if scan.CategoryName(v.Rule.Category) == "license" {
				f.risky = true
			}
		}
		rc.applyGraph(f)
		out = append(out, f)
	}
	d.runCheckers(ctx, out, st, rc)
	d.malwareAnalysis(ctx, out, st)
	for _, f := range out {
		for _, c := range f.checks {
			f.risky = f.risky || c.Category == scan.CategoryLicense
		}
	}
	return out, nil
}

// countViolations counts policy violations and checker findings.
// countSuspicious counts packages with at least one suspicious-category finding
// (typosquat, deprecated, unmaintained…). guarddog verdicts add to it later.
func countSuspicious(fs []*finding) (n int) {
	for _, f := range fs {
		for _, c := range f.checks {
			if c.Category == scan.CategorySuspicious {
				n++
				break
			}
		}
	}
	return n
}

func countViolations(fs []*finding) (n int) {
	for _, f := range fs {
		n += len(f.violations) + len(f.checks)
	}
	return n
}

// conclusion: failure when a blocking violation/finding exists in block
// mode, neutral for any other violation or finding, else success. CEL
// policy violations always block.
func conclusion(fs []*finding, st settings) string {
	blocking := false
	for _, f := range fs {
		blocking = blocking || len(f.violations) > 0 || slices.ContainsFunc(f.checks, func(c scan.Finding) bool { return c.Blocking })
	}
	switch {
	case blocking && st.BlockMode:
		return "failure"
	case countViolations(fs) > 0:
		return "neutral"
	default:
		return "success"
	}
}

var riskRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

func rank(r string) int {
	if v, ok := riskRank[r]; ok {
		return v
	}
	return 4
}

func (d Deps) report(scanID string, fs []*finding, ai []string, noChanges bool, project scan.Project) render.Report {
	r := render.Report{PublicURL: d.PublicURL, ScanID: scanID, AIUsage: ai, NoChanges: noChanges,
		Project: render.Project{Name: project.Name, License: project.License, LicenseSource: project.LicenseSource, UsageModel: project.UsageModel}}
	for _, f := range fs {
		fixed := map[string]string{}
		for _, m := range enrich.Matches(f.pkg) {
			fixed[m.AdvisoryID] = m.FixedIn
		}
		var vulns []render.Vuln
		for _, vu := range f.vulns {
			vulns = append(vulns, render.Vuln{ID: vu.ID, Risk: vu.Risk, Summary: vu.Summary, FixedIn: fixed[vu.ID]})
		}
		rp := render.Package{ID: f.componentID, Name: f.pkg.GetName(), Version: f.pkg.GetVersion(), Ecosystem: f.ecosystem(), ManifestPath: f.path,
			Malware: f.malware, Vulnerable: f.vulnerable, RiskyLicense: f.risky,
			Direct: f.direct, Depth: f.depth, Dev: f.dev != nil && *f.dev, Via: f.via, Paths: f.paths, Imported: f.imported,
			GraphSource: f.graphSource, Licenses: scan.Licenses(f.pkg), Vulns: vulns}
		r.Packages = append(r.Packages, rp)
		for _, c := range f.checks {
			r.Findings = append(r.Findings, render.Finding{Rule: c.Rule, Category: c.Category, Severity: c.Severity, Blocking: c.Blocking,
				Summary: c.Summary, Package: rp.Name + "@" + rp.Version, ManifestPath: f.path, Details: c.Details})
		}
		for _, v := range f.violations {
			cat := scan.CategoryName(v.Rule.Category)
			var top []render.Vuln
			for _, vu := range vulns {
				if (cat == "malware") == strings.HasPrefix(vu.ID, "MAL-") {
					top = append(top, vu)
				}
			}
			slices.SortStableFunc(top, func(a, b render.Vuln) int { return rank(a.Risk) - rank(b.Risk) })
			if cat != "malware" && cat != "vulnerability" {
				top = nil
			}
			r.Violations = append(r.Violations, render.Violation{Rule: v.Rule.Name, Category: cat, Summary: v.Rule.Summary,
				Package: rp, Vulns: top[:min(len(top), 3)]})
		}
	}
	// Problems first, then by path/name for stable output.
	bad := func(p render.Package) int {
		if p.Malware || p.Vulnerable || p.RiskyLicense {
			return 0
		}
		return 1
	}
	slices.SortStableFunc(r.Packages, func(a, b render.Package) int {
		if x := bad(a) - bad(b); x != 0 {
			return x
		}
		return strings.Compare(a.ManifestPath+a.Name+a.Version, b.ManifestPath+b.Name+b.Version)
	})
	return r
}

type persistIn struct {
	tenant, projectID, versionID, scanID string
	findings                             []*finding
	osvCleanRows                         bool // PR scans: record a clean OSV analysis for new packages
	replaceComponents                    bool // full scans: replace the version's component set and edges
	conclusion, reportMD                 string
	risk                                 *riskCtx // graphs (edges) and detected project license
}

// persist stores components, matches, violations and analyses and marks the
// scan successful. Must run inside db.WithTenantTx.
func persist(ctx context.Context, tx pgx.Tx, in persistIn) error {
	// 1) components, one per purl.
	compIDs := map[string]string{}
	var purls []string
	b := &pgx.Batch{}
	for _, f := range in.findings {
		purl := f.pkg.GetPackageUrl()
		if _, ok := compIDs[purl]; ok {
			continue
		}
		compIDs[purl] = ""
		purls = append(purls, purl)
		b.Queue(`INSERT INTO components (id, tenant_id, ecosystem, name, version, purl, licenses) VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (tenant_id, purl) DO UPDATE SET licenses=EXCLUDED.licenses, updated_at=now() RETURNING id`,
			ids.New(), in.tenant, f.ecosystem(), f.pkg.GetName(), f.pkg.GetVersion(), purl, scan.Licenses(f.pkg))
	}
	if len(purls) > 0 {
		br := tx.SendBatch(ctx, b)
		for _, p := range purls {
			var id string
			if err := br.QueryRow().Scan(&id); err != nil {
				br.Close()
				return fmt.Errorf("upsert component %s: %w", p, err)
			}
			compIDs[p] = id
		}
		if err := br.Close(); err != nil {
			return err
		}
	}

	// 2) everything else in one batch.
	b = &pgx.Batch{}
	b.Queue(`DELETE FROM scan_packages WHERE scan_id=$1`, in.scanID)
	b.Queue(`DELETE FROM policy_violations WHERE scan_id=$1`, in.scanID)
	if in.replaceComponents {
		b.Queue(`DELETE FROM project_version_components WHERE project_version_id=$1`, in.versionID)
		b.Queue(`DELETE FROM project_version_dependencies WHERE project_version_id=$1`, in.versionID)
	}
	var vulnCount, malCount int
	for _, f := range in.findings {
		f.componentID = compIDs[f.pkg.GetPackageUrl()]
		for _, v := range f.vulns {
			b.Queue(`INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk, fixed_in) VALUES ($1,$2,$3,$4,NULLIF($5,''))
				ON CONFLICT (component_id, advisory_id) DO UPDATE SET risk=EXCLUDED.risk, fixed_in=EXCLUDED.fixed_in`, in.tenant, f.componentID, v.ID, v.Risk, v.FixedIn)
			if !strings.HasPrefix(v.ID, "MAL-") {
				vulnCount++
			}
		}
		via, paths := f.via, f.paths
		if via == nil {
			via = []string{}
		}
		if paths == nil {
			paths = [][]string{}
		}
		b.Queue(`INSERT INTO scan_packages (tenant_id, scan_id, component_id, manifest_path, change, malware, vulnerable, risky_license,
				direct, depth, dev, via, paths, graph_source, imported)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULLIF($10,0),$11,$12,$13,$14,$15) ON CONFLICT DO NOTHING`,
			in.tenant, in.scanID, f.componentID, f.path, f.change, f.malware, f.vulnerable, f.risky,
			f.direct, f.depth, f.dev, via, mustJSON(paths), f.graphSource, f.imported)
		for _, v := range f.violations {
			cat := scan.CategoryName(v.Rule.Category)
			b.Queue(`INSERT INTO policy_violations (id, tenant_id, scan_id, project_version_id, component_id, rule_name, category, summary,
					severity, blocking, details)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true,'{}')`, ids.New(), in.tenant, in.scanID, in.versionID, f.componentID,
				v.Rule.Name, cat, v.Rule.Summary, violationSeverity(cat, f.vulns))
		}
		for _, c := range f.checks {
			details := c.Details
			if details == nil {
				details = map[string]any{}
			}
			b.Queue(`INSERT INTO policy_violations (id, tenant_id, scan_id, project_version_id, component_id, rule_name, category, summary,
					severity, blocking, details)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, ids.New(), in.tenant, in.scanID, in.versionID, f.componentID,
				c.Rule, c.Category, c.Summary, c.Severity, c.Blocking, mustJSON(details))
		}
		status := ""
		if f.malware {
			status, malCount = "malicious", malCount+1
		} else if in.osvCleanRows {
			status = "clean"
		}
		if status != "" {
			b.Queue(`INSERT INTO package_analyses (id, tenant_id, component_id, project_version_id, scan_id, status, verified, source, evidence)
				SELECT $1,$2,$3,$4,$5,$6,$7,'osv',$8
				WHERE NOT EXISTS (SELECT 1 FROM package_analyses WHERE component_id=$3 AND source='osv' AND status=$6)`,
				ids.New(), in.tenant, f.componentID, in.versionID, in.scanID, status, f.malware, mustJSON(map[string]any{"advisories": f.vulns}))
		}
		if in.replaceComponents {
			b.Queue(`INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path, direct, depth, dev)
				VALUES ($1,$2,$3,$4,$5,NULLIF($6,0),$7) ON CONFLICT DO NOTHING`, in.tenant, in.versionID, f.componentID, f.path,
				f.direct, f.depth, f.dev)
		}
	}
	if in.replaceComponents {
		b.Queue(`UPDATE project_versions SET last_scan_id=$2, updated_at=now() WHERE id=$1`, in.versionID, in.scanID)
		queueEdges(b, in, compIDs)
	}
	if rc := in.risk; rc != nil && rc.detected != nil && in.replaceComponents {
		b.Queue(`UPDATE projects SET license=$2, license_source=$3, updated_at=now()
			WHERE id=$1 AND license_source IS DISTINCT FROM 'override'`, in.projectID, rc.detected[0], rc.detected[1])
	}
	b.Queue(`UPDATE scans SET status='success', error=NULL, finished_at=now(), components_count=$2, vulns_count=$3,
		violations_count=$4, malicious_count=$5, conclusion=$6, report_md=$7, suspicious_count=$8 WHERE id=$1`,
		in.scanID, len(in.findings), vulnCount, countViolations(in.findings), malCount, in.conclusion, in.reportMD, countSuspicious(in.findings))
	// Drop raw uploaded lockfile bodies once we've committed the scan results.
	// Scans that must retry stay in a non-success state and keep their uploads;
	// non-upload scans (PR, repo) have no scan_uploads rows, so this is a no-op there.
	b.Queue(`DELETE FROM scan_uploads WHERE scan_id=$1`, in.scanID)
	return tx.SendBatch(ctx, b).Close()
}

// queueEdges writes the version's dependency edges (full scans).
func queueEdges(b *pgx.Batch, in persistIn, compIDs map[string]string) {
	if in.risk == nil {
		return
	}
	paths := make([]string, 0, len(in.risk.graphs))
	for p := range in.risk.graphs {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, mp := range paths {
		g := in.risk.graphs[mp]
		for _, e := range g.Edges() {
			child := compIDs[e[1].GetPackageUrl()]
			var parent *string
			if e[0] != nil {
				id, ok := compIDs[e[0].GetPackageUrl()]
				if !ok {
					continue
				}
				parent = &id
			}
			if child == "" {
				continue
			}
			b.Queue(`INSERT INTO project_version_dependencies (tenant_id, project_version_id, manifest_path, parent_component_id,
					child_component_id, graph_source) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
				in.tenant, in.versionID, mp, parent, child, g.Source())
		}
	}
}

// startScan marks a scan row running (attempt bookkeeping).
func startScan(ctx context.Context, tx pgx.Tx, scanID string) error {
	_, err := tx.Exec(ctx, `UPDATE scans SET status='running', started_at=now(), error=NULL WHERE id=$1`, scanID)
	return err
}

func (d Deps) finishScan(ctx context.Context, tenant, scanID, status string, cause error) {
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	err := withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE scans SET status=$2, error=NULLIF($3,''), finished_at=now() WHERE id=$1`, scanID, status, msg)
		return err
	})
	if err != nil {
		d.Logger.Error("update scan status", "scan", scanID, "err", err)
	}
}

// malwareAnalysis adds SafeDep's malware analysis verdicts (beyond the OSV
// MAL- feed): confirmed malware is malware; an unconfirmed detection is a
// blocking suspicious finding. Exclusions never hide confirmed malware.
func (d Deps) malwareAnalysis(ctx context.Context, fs []*finding, st settings) {
	if d.Malysis == nil || len(fs) == 0 {
		return
	}
	pkgs := make([]*models.Package, 0, len(fs))
	for _, f := range fs {
		if !f.malware {
			pkgs = append(pkgs, f.pkg)
		}
	}
	mctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	verdicts := d.Malysis.Query(mctx, pkgs)
	now := time.Now()
	for _, f := range fs {
		v, ok := verdicts[f.pkg]
		if !ok || !v.Malware {
			continue
		}
		details := map[string]any{"verified": v.Verified, "source": "depguard malware analysis"}
		if v.Verified {
			f.malware = true
			f.checks = append(f.checks, scan.Finding{Rule: "malware-analysis", Category: "malware", Severity: scan.SeverityCritical, Blocking: true,
				Package: f.pkg, Details: details,
				Summary: fmt.Sprintf("%s %s is confirmed malicious by depguard malware analysis.", f.pkg.GetName(), f.pkg.GetVersion())})
			continue
		}
		if len(scan.ApplyExclusions([]scan.Violation{{Package: f.pkg}}, st.Exclusions, now)) == 0 {
			continue // an accepted risk
		}
		f.checks = append(f.checks, scan.Finding{Rule: "possible-malware", Category: scan.CategorySuspicious, Severity: scan.SeverityHigh, Blocking: true,
			Package: f.pkg, Details: details,
			Summary: fmt.Sprintf("%s %s was flagged as possibly malicious by depguard malware analysis (not yet confirmed).", f.pkg.GetName(), f.pkg.GetVersion())})
	}
}
