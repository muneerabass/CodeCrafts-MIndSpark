package engine

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

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
}

func (f *finding) ecosystem() string { return f.pkg.Manifest.Ecosystem }

// evaluate enriches packages and applies the tenant policy and exclusions.
func (d Deps) evaluate(ctx context.Context, changes []scan.Change, st settings) ([]*finding, error) {
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
		out = append(out, f)
	}
	return out, nil
}

func countViolations(fs []*finding) (n int) {
	for _, f := range fs {
		n += len(f.violations)
	}
	return n
}

// conclusion: failure (block mode) / neutral (warn mode) on violations.
func conclusion(fs []*finding, st settings) string {
	switch {
	case countViolations(fs) == 0:
		return "success"
	case st.BlockMode:
		return "failure"
	default:
		return "neutral"
	}
}

var riskRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

func rank(r string) int {
	if v, ok := riskRank[r]; ok {
		return v
	}
	return 4
}

func (d Deps) report(scanID string, fs []*finding, ai []string, noChanges bool) render.Report {
	r := render.Report{PublicURL: d.PublicURL, ScanID: scanID, AIUsage: ai, NoChanges: noChanges}
	for _, f := range fs {
		rp := render.Package{Name: f.pkg.GetName(), Version: f.pkg.GetVersion(), Ecosystem: f.ecosystem(), ManifestPath: f.path,
			Malware: f.malware, Vulnerable: f.vulnerable, RiskyLicense: f.risky}
		r.Packages = append(r.Packages, rp)
		for _, v := range f.violations {
			cat := scan.CategoryName(v.Rule.Category)
			var top []render.Vuln
			for _, vu := range f.vulns {
				if (cat == "malware") == strings.HasPrefix(vu.ID, "MAL-") {
					top = append(top, render.Vuln{ID: vu.ID, Risk: vu.Risk})
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
	replaceComponents                    bool // full scans: replace the version's component set
	conclusion, reportMD                 string
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
	}
	var vulnCount, malCount int
	for _, f := range in.findings {
		f.componentID = compIDs[f.pkg.GetPackageUrl()]
		for _, v := range f.vulns {
			b.Queue(`INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk) VALUES ($1,$2,$3,$4)
				ON CONFLICT (component_id, advisory_id) DO UPDATE SET risk=EXCLUDED.risk`, in.tenant, f.componentID, v.ID, v.Risk)
			if !strings.HasPrefix(v.ID, "MAL-") {
				vulnCount++
			}
		}
		b.Queue(`INSERT INTO scan_packages (tenant_id, scan_id, component_id, manifest_path, change, malware, vulnerable, risky_license)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
			in.tenant, in.scanID, f.componentID, f.path, f.change, f.malware, f.vulnerable, f.risky)
		for _, v := range f.violations {
			b.Queue(`INSERT INTO policy_violations (id, tenant_id, scan_id, project_version_id, component_id, rule_name, category, summary)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, ids.New(), in.tenant, in.scanID, in.versionID, f.componentID,
				v.Rule.Name, scan.CategoryName(v.Rule.Category), v.Rule.Summary)
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
			b.Queue(`INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path)
				VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, in.tenant, in.versionID, f.componentID, f.path)
		}
	}
	if in.replaceComponents {
		b.Queue(`UPDATE project_versions SET last_scan_id=$2, updated_at=now() WHERE id=$1`, in.versionID, in.scanID)
	}
	b.Queue(`UPDATE scans SET status='success', error=NULL, finished_at=now(), components_count=$2, vulns_count=$3,
		violations_count=$4, malicious_count=$5, conclusion=$6, report_md=$7 WHERE id=$1`,
		in.scanID, len(in.findings), vulnCount, countViolations(in.findings), malCount, in.conclusion, in.reportMD)
	return tx.SendBatch(ctx, b).Close()
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
