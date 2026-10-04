package scan

import (
	"path"
	"strings"
	"time"

	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
)

// IsManifest reports whether vet can parse the repo path as a dependency
// manifest/lockfile (vet's own parser lookup decides). package.json is skipped:
// it carries ranges, not resolved versions, and its lockfile is scanned instead.
func IsManifest(repoPath string) bool {
	if path.Base(repoPath) == "package.json" {
		return false
	}
	_, err := parser.FindParser(repoPath, "")
	return err == nil
}

// Vuln is one advisory matched to a package.
type Vuln struct {
	ID      string
	Summary string
	Risk    string // CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
	FixedIn string // lowest fixed version above the installed one; "" if none
}

// fixedInPrefix mirrors enrich's encoding of FixedIn in PackageVulnerability.Related
// (scan cannot import enrich).
const fixedInPrefix = "depguard:fixed-in="

// Vulns reads matched advisories from pkg.Insights (first CVSS v3/v2 risk).
func Vulns(pkg *models.Package) []Vuln {
	if pkg.Insights == nil || pkg.Insights.Vulnerabilities == nil {
		return nil
	}
	var out []Vuln
	for _, v := range *pkg.Insights.Vulnerabilities {
		if v.Id == nil {
			continue
		}
		vu := Vuln{ID: *v.Id, Risk: "UNKNOWN"}
		if v.Summary != nil {
			vu.Summary = *v.Summary
		}
		if v.Related != nil {
			for _, r := range *v.Related {
				if strings.HasPrefix(r, fixedInPrefix) {
					vu.FixedIn = strings.TrimPrefix(r, fixedInPrefix)
				}
			}
		}
		if v.Severities != nil {
			for _, s := range *v.Severities {
				if s.Type != nil && s.Risk != nil && (*s.Type == insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3 || *s.Type == insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2) {
					vu.Risk = string(*s.Risk)
					break
				}
			}
		}
		out = append(out, vu)
	}
	return out
}

// IsMalicious reports a MAL- (OpenSSF malicious-packages) advisory hit.
func IsMalicious(pkg *models.Package) bool {
	for _, v := range Vulns(pkg) {
		if strings.HasPrefix(v.ID, "MAL-") {
			return true
		}
	}
	return false
}

// Licenses returns SPDX ids from insights.
func Licenses(pkg *models.Package) []string {
	if pkg.Insights == nil || pkg.Insights.Licenses == nil {
		return []string{}
	}
	out := []string{}
	for _, l := range *pkg.Insights.Licenses {
		out = append(out, string(l))
	}
	return out
}

// Exclusion is an active row of the tenant's exclusions table.
type Exclusion struct {
	Ecosystem string
	Name      string
	Version   string // "*" = all versions
	ExpiresAt *time.Time
}

func (e Exclusion) matches(eco, name, version string, now time.Time) bool {
	if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
		return false
	}
	return strings.EqualFold(e.Ecosystem, eco) && strings.EqualFold(e.Name, name) &&
		(e.Version == "*" || e.Version == "" || e.Version == version)
}

// ApplyExclusions drops violations on excluded packages. A known-malicious
// (MAL-) package keeps its malware violations: exclusions never hide malware.
func ApplyExclusions(vs []Violation, ex []Exclusion, now time.Time) []Violation {
	var out []Violation
	for _, v := range vs {
		p := v.Package
		eco := p.Manifest.Ecosystem
		excluded := false
		for _, e := range ex {
			if e.matches(eco, p.GetName(), p.GetVersion(), now) {
				excluded = true
				break
			}
		}
		if !excluded || (v.Rule.Category == checks.CheckType_CheckTypeMalware && IsMalicious(p)) {
			out = append(out, v)
		}
	}
	return out
}

// Change is a package that a PR adds or changes.
type Change struct {
	Package *models.Package
	Path    string // manifest display path
	Kind    string // added | changed
	Old     string // for "changed": a version of the same package in the base manifest
}

// Diff returns packages present in head but not in base, keyed by
// (manifest path, ecosystem, name, version). A package whose name exists in
// the same base manifest under another version is "changed", else "added".
// Like vet-action, base packages act as exceptions so only new code is judged.
func Diff(base, head []*models.PackageManifest) []Change {
	type nameKey struct{ path, eco, name string }
	baseVersions := map[nameKey]map[string]bool{}
	for _, m := range base {
		for _, p := range m.GetPackages() {
			k := nameKey{m.GetDisplayPath(), m.Ecosystem, p.GetName()}
			if baseVersions[k] == nil {
				baseVersions[k] = map[string]bool{}
			}
			baseVersions[k][p.GetVersion()] = true
		}
	}
	seen := map[string]bool{}
	var out []Change
	for _, m := range head {
		for _, p := range m.GetPackages() {
			k := nameKey{m.GetDisplayPath(), m.Ecosystem, p.GetName()}
			full := k.path + "\x00" + k.eco + "\x00" + k.name + "\x00" + p.GetVersion()
			if seen[full] || baseVersions[k][p.GetVersion()] {
				continue
			}
			seen[full] = true
			kind, old := "added", ""
			if len(baseVersions[k]) > 0 {
				kind = "changed"
				for v := range baseVersions[k] {
					if old == "" || v < old { // deterministic pick when the base held several
						old = v
					}
				}
			}
			out = append(out, Change{Package: p, Path: m.GetDisplayPath(), Kind: kind, Old: old})
		}
	}
	return out
}

// SBOMFormat returns vet's --lockfile-as value for SBOM files (*.cdx.json,
// *.spdx.json), "" for anything else.
func SBOMFormat(repoPath string) string {
	switch b := path.Base(repoPath); {
	case strings.HasSuffix(b, ".cdx.json") || b == "bom.json":
		return parser.LockfileAsBomCycloneDx
	case strings.HasSuffix(b, ".spdx.json"):
		return parser.LockfileAsBomSpdx
	}
	return ""
}
