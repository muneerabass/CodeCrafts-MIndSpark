package engine

import (
	"context"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/depguard/depguard/internal/scan"
	"github.com/google/go-github/v92/github"
	"github.com/safedep/vet/pkg/models"
	"golang.org/x/sync/errgroup"
)

// riskInput is what a scan knows beyond its lockfiles.
type riskInput struct {
	// aux holds lockfiles, direct-dependency manifests and root license
	// files (path → content) of the scanned revision.
	aux map[string][]byte
	// sources is app source for import detection; nil = not available.
	sources    map[string][]byte
	githubSPDX string
	project    scan.Project
}

// riskCtx is per-scan graph context, built once from the head manifests.
type riskCtx struct {
	graphs  map[string]*scan.Graph // by manifest display path
	imports map[string]bool        // nil = unknown
	project scan.Project
	// detected is a newly detected project license to store (full scans).
	detected *[2]string
}

// isRootLicense matches LICENSE*/LICENCE*/COPYING* at the repository root.
func isRootLicense(p string) bool {
	if strings.Contains(p, "/") {
		return false
	}
	b := strings.ToUpper(p)
	return strings.HasPrefix(b, "LICENSE") || strings.HasPrefix(b, "LICENCE") || strings.HasPrefix(b, "COPYING")
}

func skipped(p string, dirs map[string]bool) bool {
	return slices.ContainsFunc(strings.Split(path.Dir(p), "/"), func(s string) bool { return dirs[s] })
}

var sourceSkipDirs = map[string]bool{"node_modules": true, "vendor": true, "testdata": true, "fixtures": true,
	"test-fixtures": true, "__fixtures__": true, "dist": true, "build": true, ".git": true}

// auxEntries picks direct-dependency manifests in lockfile dirs and root
// manifests and license files from a tree.
func auxEntries(blobs map[string]*github.TreeEntry, lockPaths []string) []*github.TreeEntry {
	dirs := map[string]bool{".": true}
	for _, p := range lockPaths {
		dirs[path.Dir(p)] = true
	}
	var out []*github.TreeEntry
	for p, e := range blobs {
		if e.GetSize() > maxManifestBytes || slices.Contains(lockPaths, p) {
			continue
		}
		if isRootLicense(p) || (scan.IsDirectManifest(p) && dirs[path.Dir(p)] && !skipped(p, skipDirs)) {
			out = append(out, e)
		}
	}
	return out
}

// sourceEntries picks app source files for import detection within budget,
// shallowest first.
func sourceEntries(blobs map[string]*github.TreeEntry) []*github.TreeEntry {
	var all []*github.TreeEntry
	for p, e := range blobs {
		if sourceExts[path.Ext(p)] && e.GetSize() <= maxSourceBytes && !skipped(p, sourceSkipDirs) {
			all = append(all, e)
		}
	}
	slices.SortFunc(all, func(a, b *github.TreeEntry) int {
		if x := strings.Count(a.GetPath(), "/") - strings.Count(b.GetPath(), "/"); x != 0 {
			return x
		}
		return strings.Compare(a.GetPath(), b.GetPath())
	})
	var out []*github.TreeEntry
	total := 0
	for _, e := range all {
		if len(out) == maxImportFiles {
			break
		}
		if total+e.GetSize() > maxImportTotal {
			continue
		}
		total += e.GetSize()
		out = append(out, e)
	}
	return out
}

// fetchEntries downloads blobs concurrently; failures are skipped (best effort).
func fetchEntries(ctx context.Context, gh *github.Client, owner, repo string, entries []*github.TreeEntry, limit int64) map[string][]byte {
	out := map[string][]byte{}
	var mu sync.Mutex
	var g errgroup.Group
	g.SetLimit(8)
	for _, e := range entries {
		g.Go(func() error {
			b, err := fetchBlob(ctx, gh, owner, repo, e.GetSHA(), limit)
			if err == nil {
				mu.Lock()
				out[e.GetPath()] = b
				mu.Unlock()
			}
			return nil
		})
	}
	g.Wait()
	return out
}

// githubLicense returns the repo's license SPDX id from GitHub; "" on error.
func githubLicense(ctx context.Context, gh *github.Client, owner, repo string) string {
	rl, _, err := gh.Repositories.License(ctx, owner, repo)
	if err != nil {
		return ""
	}
	if id := rl.GetLicense().GetSPDXID(); id != "NOASSERTION" {
		return id
	}
	return ""
}

// repoInputs fetches what a scan of a GitHub revision needs beyond its
// lockfiles: manifests, root license files and app source.
func (d Deps) repoInputs(ctx context.Context, gh *github.Client, owner, repo string, blobs map[string]*github.TreeEntry, lockfiles []file, project scan.Project) riskInput {
	in := riskInput{aux: map[string][]byte{}, project: project}
	var lockPaths []string
	for _, f := range lockfiles {
		in.aux[f.Path] = f.Data
		lockPaths = append(lockPaths, f.Path)
	}
	if blobs != nil {
		for p, b := range fetchEntries(ctx, gh, owner, repo, auxEntries(blobs, lockPaths), maxManifestBytes) {
			in.aux[p] = b
		}
		in.sources = fetchEntries(ctx, gh, owner, repo, sourceEntries(blobs), maxSourceBytes)
	}
	if d.DetectLicense != nil && project.LicenseSource != "override" {
		in.githubSPDX = githubLicense(ctx, gh, owner, repo)
	}
	return in
}

// depsDevGrapher is implemented by *enrich.Enricher.
type depsDevGrapher interface {
	DepsDevGraph(ctx context.Context, eco, name, version string) ([]scan.GraphNode, [][2]int, error)
}

// buildRisk builds dependency graphs for manifests, import detection and
// the project license context.
func (d Deps) buildRisk(ctx context.Context, manifests []*models.PackageManifest, in riskInput) *riskCtx {
	rc := &riskCtx{graphs: map[string]*scan.Graph{}, project: in.project}
	if rc.project.UsageModel == "" {
		rc.project.UsageModel = scan.UsageDistributedBinary
	}
	dd, _ := d.Enricher.(depsDevGrapher)
	for _, m := range manifests {
		p := m.GetDisplayPath()
		if path.Base(p) == "package-lock.json" {
			scan.AddNpmLockEdges(m, in.aux[p])
		}
		siblings := map[string][]byte{}
		for fp, b := range in.aux {
			if path.Dir(fp) == path.Dir(p) {
				siblings[fp] = b
			}
		}
		var fetch scan.DepsDevFunc
		if dd != nil {
			eco := m.Ecosystem
			// ponytail: sequential deps.dev calls (cached 7 days); parallelize if cold scans of big Go/Maven repos get slow.
			fetch = func(name, version string) ([]scan.GraphNode, [][2]int) {
				nodes, edges, err := dd.DepsDevGraph(ctx, eco, name, version)
				if err != nil {
					d.Logger.Warn("deps.dev graph", "pkg", name, "version", version, "err", err)
				}
				return nodes, edges
			}
		}
		rc.graphs[p] = scan.BuildGraphWith(m, scan.ReadDirectDeps(m.Ecosystem, siblings), fetch)
	}
	if in.sources != nil {
		rc.imports = scan.ImportedPackages(in.sources)
	}
	if d.DetectLicense != nil && rc.project.LicenseSource != "override" {
		root := map[string][]byte{}
		for fp, b := range in.aux {
			if !strings.Contains(fp, "/") {
				root[fp] = b
			}
		}
		if expr, src := d.DetectLicense(root, in.githubSPDX); expr != "" {
			rc.project.License, rc.project.LicenseSource = expr, src
			rc.detected = &[2]string{expr, src}
		}
	}
	return rc
}

// applyGraph fills a finding's graph fields.
func (rc *riskCtx) applyGraph(f *finding) {
	f.graphSource = scan.GraphNone
	g := rc.graphs[f.path]
	if g == nil {
		return
	}
	in, ok := g.Info(f.pkg)
	if !ok {
		return
	}
	f.graphSource = g.Source()
	f.direct, f.dev = &in.Direct, &in.Dev
	f.depth = in.Depth
	f.approximate = in.Approximate
	var heads []*models.Package
	for _, p := range in.Paths {
		f.paths = append(f.paths, scan.Chain(p))
		if !slices.Contains(heads, p[0]) {
			heads = append(heads, p[0])
		}
	}
	if len(f.paths) > 0 {
		f.via = f.paths[0]
	}
	if rc.imports == nil {
		return
	}
	for _, h := range heads {
		imp, known := scan.Imported(rc.imports, f.ecosystem(), h.GetName())
		if known && (f.imported == nil || imp) {
			f.imported = &imp
		}
	}
}

// runCheckers runs the risk checkers on the evaluated packages and attaches
// their findings (excluded packages get none). Checker errors only log.
func (d Deps) runCheckers(ctx context.Context, fs []*finding, st settings, rc *riskCtx) {
	if d.Checkers == nil || len(fs) == 0 {
		return
	}
	checkers := d.Checkers(st.Policy, rc.project)
	if len(checkers) == 0 {
		return
	}
	in := scan.CheckInput{Project: rc.project, Context: map[*models.Package]scan.PackageContext{}}
	byPkg := map[*models.Package]*finding{}
	for _, f := range fs {
		in.Packages = append(in.Packages, f.pkg)
		byPkg[f.pkg] = f
		pc := scan.PackageContext{Direct: f.direct, Depth: f.depth, Imported: f.imported}
		if f.dev != nil {
			pc.Dev = *f.dev
		}
		in.Context[f.pkg] = pc
	}
	now := time.Now()
	for _, c := range checkers {
		out, err := c.Check(ctx, in)
		if err != nil {
			d.Logger.Warn("checker failed", "checker", c.Name(), "err", err)
		}
		for _, x := range out {
			f := byPkg[x.Package]
			if f == nil || len(scan.ApplyExclusions([]scan.Violation{{Package: x.Package}}, st.Exclusions, now)) == 0 {
				continue
			}
			if (x.Category == scan.CategorySuspicious || x.Category == scan.CategoryLicense) && trusted(st.Policy, x.Package) {
				continue // an allow rule marks this package as trusted
			}
			f.checks = append(f.checks, x)
		}
	}
}

// violationSeverity: malware critical, vulnerability = highest matched
// risk, license high, others medium.
func violationSeverity(category string, vulns []scan.Vuln) string {
	switch category {
	case "malware":
		return scan.SeverityCritical
	case "license":
		return scan.SeverityHigh
	case "vulnerability":
		best := ""
		for _, v := range vulns {
			if !strings.HasPrefix(v.ID, "MAL-") && (best == "" || rank(v.Risk) < rank(best)) {
				best = v.Risk
			}
		}
		if s := strings.ToLower(best); s == scan.SeverityCritical || s == scan.SeverityHigh || s == scan.SeverityMedium || s == scan.SeverityLow {
			return s
		}
		return scan.SeverityHigh
	}
	return scan.SeverityMedium
}
