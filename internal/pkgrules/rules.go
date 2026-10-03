// Package pkgrules enforces the team's package and version rules: banned
// packages, allowed version ranges (minimum/maximum) and trusted packages.
// It runs as a scan.Checker on every scan and on pre-install checks.
package pkgrules

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/safedep/vet/pkg/models"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/scan"
)

const (
	Category    = "policy"
	RuleDenied  = "package-denied"
	RuleVersion = "version-not-allowed"
	MaxRules    = 500
)

// ecoAliases accepts the names people type for an ecosystem.
var ecoAliases = map[string]string{
	"npm": "npm", "pypi": "PyPI", "python": "PyPI", "pip": "PyPI", "go": "Go", "golang": "Go",
	"cargo": "crates.io", "crates.io": "crates.io", "rust": "crates.io", "maven": "Maven",
	"rubygems": "RubyGems", "packagist": "Packagist", "nuget": "NuGet",
}

// Ecosystem normalizes a rule or request ecosystem to its OSV name ("" if unknown).
func Ecosystem(s string) string { return ecoAliases[strings.ToLower(strings.TrimSpace(s))] }

// Validate checks a rule list as saved from the Policy page or a .depguard.yml.
func Validate(rules []scan.PackageRule) error {
	if len(rules) > MaxRules {
		return fmt.Errorf("at most %d package rules", MaxRules)
	}
	for i, r := range rules {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("package rule %d: name is required", i+1)
		}
		if r.Ecosystem != "" && Ecosystem(r.Ecosystem) == "" {
			return fmt.Errorf("package rule %d: unknown ecosystem %q", i+1, r.Ecosystem)
		}
		if r.Deny && r.Allow {
			return fmt.Errorf("package rule %d (%s): cannot both deny and allow", i+1, r.Name)
		}
		if _, err := ParseRange(r.Versions); err != nil {
			return fmt.Errorf("package rule %d (%s): %w", i+1, r.Name, err)
		}
		switch r.Severity {
		case "", scan.SeverityCritical, scan.SeverityHigh, scan.SeverityMedium, scan.SeverityLow, scan.SeverityInfo:
		default:
			return fmt.Errorf("package rule %d (%s): unknown severity %q", i+1, r.Name, r.Severity)
		}
	}
	return nil
}

// Checker reports packages that break the rules.
type Checker struct{ rules []scan.PackageRule }

func New(rules []scan.PackageRule) Checker { return Checker{rules} }

func (Checker) Name() string { return "package-rules" }

func (c Checker) Check(_ context.Context, in scan.CheckInput) ([]scan.Finding, error) {
	var out []scan.Finding
	for _, p := range in.Packages {
		out = append(out, c.Findings(p)...)
	}
	return out, nil
}

// Findings returns the rule violations for one package.
func (c Checker) Findings(p *models.Package) []scan.Finding {
	eco, name, version := enrich.OSVEcosystem(p), p.GetName(), p.GetVersion()
	var out []scan.Finding
	for _, r := range c.rules {
		if !matches(r, eco, name) {
			continue
		}
		sev := r.Severity
		if sev == "" {
			sev = scan.SeverityHigh
		}
		blocking := sev == scan.SeverityCritical || sev == scan.SeverityHigh
		details := map[string]any{"rule_name": r.Name, "reason": r.Reason}
		why := ""
		if r.Reason != "" {
			why = " Reason: " + r.Reason
		}
		switch {
		case r.Deny:
			out = append(out, scan.Finding{Rule: RuleDenied, Category: Category, Severity: sev, Blocking: blocking, Package: p, Details: details,
				Summary: fmt.Sprintf("%s is banned by your team's package rules.%s", name, why)})
		case r.Versions != "":
			rng, err := ParseRange(r.Versions)
			if err != nil {
				continue // validated on save; ignore a bad stored rule rather than fail scans
			}
			if ok, err := rng.Contains(eco, version); err == nil && !ok {
				details["allowed"] = r.Versions
				out = append(out, scan.Finding{Rule: RuleVersion, Category: Category, Severity: sev, Blocking: blocking, Package: p, Details: details,
					Summary: fmt.Sprintf("%s %s is outside the allowed versions %s.%s", name, version, r.Versions, why)})
			}
		}
	}
	return out
}

// Trusted reports whether an allow rule marks the package as trusted.
func Trusted(rules []scan.PackageRule, p *models.Package) bool {
	eco := enrich.OSVEcosystem(p)
	for _, r := range rules {
		if r.Allow && matches(r, eco, p.GetName()) {
			return true
		}
	}
	return false
}

func matches(r scan.PackageRule, eco, name string) bool {
	if r.Ecosystem != "" && Ecosystem(r.Ecosystem) != eco {
		return false
	}
	pat, n := normName(eco, r.Name), normName(eco, name)
	if !strings.Contains(pat, "*") {
		return pat == n
	}
	re, err := regexp.Compile("^" + strings.ReplaceAll(regexp.QuoteMeta(pat), `\*`, ".*") + "$")
	return err == nil && re.MatchString(n)
}

// normName compares names case-insensitively; PyPI also treats - _ . alike (PEP 503).
func normName(eco, n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if eco == "PyPI" {
		n = strings.NewReplacer("_", "-", ".", "-").Replace(n)
	}
	return n
}
