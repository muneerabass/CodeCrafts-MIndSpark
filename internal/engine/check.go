package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/pkg/models"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/pkgrules"
	"github.com/depguard/depguard/internal/scan"
)

// Pre-install check (POST /v1/packages/check): the packages a developer is
// about to install go through the same pipeline as a scan (OSV vulnerabilities
// and malware, CEL policy, suspicious/license checkers, package rules,
// exclusions) plus SafeDep's community malware verdicts, without persisting.

const (
	DecisionAllow = "allow"
	DecisionWarn  = "warn"
	DecisionBlock = "block"

	MaxCheckPackages = 3000
	checkDeadline    = 20 * time.Second
)

type CheckPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Direct    *bool  `json:"direct,omitempty"`
}

// CheckRequest lists packages directly and/or as lockfiles: with After set,
// only packages added or changed relative to Before are checked, and
// Manifests (package.json, go.mod, Cargo.toml, ...) mark direct dependencies.
type CheckRequest struct {
	Packages  []CheckPackage     `json:"packages"`
	Before    []CheckFile        `json:"before"`
	After     []CheckFile        `json:"after"`
	Manifests []CheckFile        `json:"manifests"`
	RepoRules []scan.PackageRule `json:"repo_rules"`
}

type CheckFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type CheckFinding struct {
	Rule     string `json:"rule"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Blocking bool   `json:"blocking"`
	Summary  string `json:"summary"`
	FixedIn  string `json:"fixed_in,omitempty"`
	URL      string `json:"url,omitempty"`
}

type CheckVerdict struct {
	CheckPackage
	Via      []string       `json:"via,omitempty"` // shortest chain from the app, direct dependency first
	Decision string         `json:"decision"`
	Findings []CheckFinding `json:"findings"`
}

type CheckResult struct {
	Decision  string         `json:"decision"`
	BlockMode bool           `json:"block_mode"`
	Checked   int            `json:"checked"`
	Packages  []CheckVerdict `json:"packages"` // only packages with findings, worst first
}

var vetEcosystems = map[string]string{
	"npm": models.EcosystemNpm, "PyPI": models.EcosystemPyPI, "Go": models.EcosystemGo, "crates.io": models.EcosystemCargo,
	"Maven": models.EcosystemMaven, "RubyGems": models.EcosystemRubyGems, "Packagist": models.EcosystemPackagist, "NuGet": models.EcosystemNuGet,
}

// CheckPackages evaluates packages for a tenant and returns the install decision.
func (d Deps) CheckPackages(ctx context.Context, tenant string, req CheckRequest) (*CheckResult, error) {
	if len(req.Before)+len(req.After)+len(req.Manifests) > 20 {
		return nil, fmt.Errorf("at most 20 files per check")
	}
	if len(req.Packages) > MaxCheckPackages {
		return nil, fmt.Errorf("at most %d packages per check", MaxCheckPackages)
	}
	if err := pkgrules.Validate(req.RepoRules); err != nil {
		return nil, fmt.Errorf("repo rules: %w", err)
	}
	var st settings
	if err := db.WithTenantTx(ctx, d.Pool, tenant, func(tx pgx.Tx) (err error) {
		st, err = loadSettings(ctx, tx)
		return err
	}); err != nil {
		return nil, err
	}

	pkgs := make([]*models.Package, 0, len(req.Packages))
	reqOf := map[*models.Package]CheckPackage{}
	changes := make([]scan.Change, 0, len(req.Packages))
	rc := &riskCtx{project: scan.Project{UsageModel: scan.UsageDistributedBinary}, graphs: map[string]*scan.Graph{}}
	if len(req.After) > 0 {
		before, err := parseCheckFiles(req.Before)
		if err != nil {
			return nil, err
		}
		after, err := parseCheckFiles(req.After)
		if err != nil {
			return nil, err
		}
		siblings := map[string][]byte{}
		for _, f := range req.Manifests {
			siblings[f.Path] = []byte(f.Content)
		}
		for _, m := range after {
			for _, f := range req.After {
				if f.Path == m.GetDisplayPath() {
					scan.AddLockEdges(m, f.Path, []byte(f.Content))
				}
			}
			rc.graphs[m.GetDisplayPath()] = scan.BuildGraph(m, scan.ReadDirectDeps(m.Ecosystem, siblings))
		}
		self := projectNames(req.Manifests)
		for _, c := range scan.Diff(before, after) {
			if self[strings.ToLower(c.Package.GetName())] {
				continue // the project itself appears in uv.lock / Cargo.lock / poetry.lock
			}
			pkgs = append(pkgs, c.Package)
			changes = append(changes, c)
		}
	}
	for _, cp := range req.Packages {
		eco := vetEcosystems[pkgrules.Ecosystem(cp.Ecosystem)]
		if eco == "" || strings.TrimSpace(cp.Name) == "" || strings.TrimSpace(cp.Version) == "" {
			return nil, fmt.Errorf("package %q: ecosystem (npm, pypi, go, cargo, ...), name and version are required", cp.Name)
		}
		p := &models.Package{Manifest: models.NewPackageManifestFromLocal("install", eco)}
		p.Name, p.Version = strings.TrimSpace(cp.Name), strings.TrimSpace(cp.Version)
		pkgs = append(pkgs, p)
		reqOf[p] = cp
		changes = append(changes, scan.Change{Package: p, Path: "install", Kind: "added"})
	}

	ectx, cancel := context.WithTimeout(ctx, checkDeadline)
	defer cancel()

	if len(changes) > MaxCheckPackages {
		return nil, fmt.Errorf("at most %d packages per check", MaxCheckPackages)
	}
	fs, err := d.evaluate(ectx, changes, st, rc)
	if err != nil {
		return nil, err
	}
	extra := pkgrules.New(req.RepoRules)

	res := &CheckResult{Decision: DecisionAllow, BlockMode: st.BlockMode, Checked: len(pkgs)}
	now := time.Now()
	for _, f := range fs {
		cp, ok := reqOf[f.pkg]
		if !ok {
			cp = CheckPackage{Ecosystem: enrich.OSVEcosystem(f.pkg), Name: f.pkg.GetName(), Version: f.pkg.GetVersion(), Direct: f.direct}
		}
		v := CheckVerdict{CheckPackage: cp, Via: f.via, Decision: DecisionAllow}
		malware := f.malware
		for _, x := range f.violations {
			cat := scan.CategoryName(x.Rule.Category)
			v.Findings = append(v.Findings, CheckFinding{Rule: x.Rule.Name, Category: cat, Severity: violationSeverity(cat, f.vulns),
				Blocking: true, Summary: violationSummary(x, f.vulns), FixedIn: bestFix(f.pkg, f.vulns)})
		}
		// Advisories below the policy threshold are still shown, as warnings.
		if f.vulnerable && !slices.ContainsFunc(f.violations, func(x scan.Violation) bool { return scan.CategoryName(x.Rule.Category) == "vulnerability" }) {
			sev := violationSeverity("vulnerability", f.vulns)
			v.Findings = append(v.Findings, CheckFinding{Rule: "known-vulnerability", Category: "vulnerability", Severity: sev,
				Summary: violationSummary(scan.Violation{Rule: scan.Rule{Category: checks.CheckType_CheckTypeVulnerability}, Package: f.pkg}, f.vulns) + " (below your policy's blocking threshold)",
				FixedIn: bestFix(f.pkg, f.vulns)})
		}
		for _, x := range f.checks {
			url, _ := x.Details["report_url"].(string)
			v.Findings = append(v.Findings, CheckFinding{Rule: x.Rule, Category: x.Category, Severity: x.Severity, Blocking: x.Blocking, Summary: x.Summary, URL: url})
		}
		// Repo rules (.depguard.yml) only add findings; exclusions still apply like team rules.
		if len(scan.ApplyExclusions([]scan.Violation{{Package: f.pkg}}, st.Exclusions, now)) > 0 {
			for _, x := range extra.Findings(f.pkg) {
				v.Findings = append(v.Findings, CheckFinding{Rule: x.Rule, Category: x.Category, Severity: x.Severity, Blocking: x.Blocking, Summary: x.Summary + " (repo rule)"})
			}
		}
		if len(v.Findings) == 0 {
			continue
		}
		blocking := false
		for _, x := range v.Findings {
			blocking = blocking || x.Blocking
		}
		switch {
		case malware || (blocking && st.BlockMode): // malware blocks even in warn mode
			v.Decision = DecisionBlock
		default:
			v.Decision = DecisionWarn
		}
		res.Packages = append(res.Packages, v)
		res.Decision = worse(res.Decision, v.Decision)
	}
	sortVerdicts(res.Packages)
	return res, nil
}

func violationSummary(v scan.Violation, vulns []scan.Vuln) string {
	if scan.CategoryName(v.Rule.Category) == "vulnerability" && len(vulns) > 0 {
		ids := make([]string, 0, len(vulns))
		for _, x := range vulns {
			if !strings.HasPrefix(x.ID, "MAL-") {
				ids = append(ids, x.ID+" ("+strings.ToLower(x.Risk)+")")
			}
		}
		if len(ids) > 4 {
			ids = append(ids[:4], fmt.Sprintf("+%d more", len(ids)-4))
		}
		return fmt.Sprintf("%s %s: %s", v.Package.GetName(), v.Package.GetVersion(), strings.Join(ids, ", "))
	}
	if v.Rule.Summary != "" {
		return v.Rule.Summary
	}
	return v.Rule.Name
}

// bestFix is the highest fixed version among the advisories (fixes them all).
func bestFix(pkg *models.Package, vulns []scan.Vuln) string {
	eco, best := enrich.OSVEcosystem(pkg), ""
	for _, v := range vulns {
		if v.FixedIn == "" {
			continue
		}
		if c, err := enrich.CompareVersions(eco, v.FixedIn, best); best == "" || (err == nil && c > 0) {
			best = v.FixedIn
		}
	}
	return best
}

var decisionRank = map[string]int{DecisionAllow: 0, DecisionWarn: 1, DecisionBlock: 2}

func worse(a, b string) string {
	if decisionRank[b] > decisionRank[a] {
		return b
	}
	return a
}

func sortVerdicts(vs []CheckVerdict) {
	slices.SortStableFunc(vs, func(a, b CheckVerdict) int { return decisionRank[b.Decision] - decisionRank[a.Decision] })
}

// parseCheckFiles parses uploaded lockfiles with vet's parsers.
func parseCheckFiles(files []CheckFile) ([]*models.PackageManifest, error) {
	if len(files) == 0 {
		return nil, nil
	}
	dir, err := os.MkdirTemp("", "depguard-check-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	var lfs []scan.Lockfile
	for i, f := range files {
		if len(f.Content) > 10<<20 {
			return nil, fmt.Errorf("%s exceeds 10 MB", f.Path)
		}
		// Each file keeps its base name (format detection) in its own directory.
		sub := filepath.Join(dir, strconv.Itoa(i))
		if err := os.Mkdir(sub, 0o700); err != nil {
			return nil, err
		}
		local := filepath.Join(sub, filepath.Base(filepath.Clean("/"+f.Path)))
		if err := os.WriteFile(local, []byte(f.Content), 0o600); err != nil {
			return nil, err
		}
		lfs = append(lfs, scan.Lockfile{Path: local, RepoPath: f.Path})
	}
	return scan.Parse(lfs)
}

var (
	tomlSection = regexp.MustCompile(`(?m)^\[(project|tool\.poetry|package)\]\s*$`)
	tomlName    = regexp.MustCompile(`(?m)^name\s*=\s*["']([^"']+)["']`)
)

// projectNames are the names the project itself carries in its manifests.
func projectNames(files []CheckFile) map[string]bool {
	out := map[string]bool{}
	for _, f := range files {
		switch filepath.Base(f.Path) {
		case "package.json":
			var m struct {
				Name string `json:"name"`
			}
			if json.Unmarshal([]byte(f.Content), &m) == nil && m.Name != "" {
				out[strings.ToLower(m.Name)] = true
			}
		case "pyproject.toml", "Cargo.toml":
			for _, loc := range tomlSection.FindAllStringIndex(f.Content, -1) {
				rest := f.Content[loc[1]:]
				if next := strings.Index(rest, "\n["); next >= 0 {
					rest = rest[:next]
				}
				if m := tomlName.FindStringSubmatch(rest); m != nil {
					out[strings.ToLower(m[1])] = true
				}
			}
		}
	}
	return out
}
