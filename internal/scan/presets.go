package scan

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/safedep/vet/gen/checks"
)

// PolicyConfig is tenant_settings.policy as edited on the Policy page
// (GET/PUT /api/v1/policy).
type PolicyConfig struct {
	Presets *Presets     `json:"presets,omitempty"`
	Custom  []CustomRule `json:"custom,omitempty"`
}

type Presets struct {
	Vulnerability struct {
		MinRisk string `json:"min_risk"` // CRITICAL | HIGH | MEDIUM | LOW | OFF
	} `json:"vulnerability"`
	Malware struct {
		Enabled bool `json:"enabled"`
	} `json:"malware"`
	License    LicensePreset     `json:"license"`
	Suspicious *SuspiciousPreset `json:"suspicious,omitempty"` // nil = DefaultSuspicious()
	Popularity struct {
		Enabled  bool `json:"enabled"`
		MinStars int  `json:"min_stars"`
	} `json:"popularity"`
	Maintenance struct {
		Enabled      bool    `json:"enabled"`
		MinScorecard float64 `json:"min_scorecard"`
	} `json:"maintenance"`
	// Packages are package and version rules: banned packages, allowed
	// version ranges (minimum/maximum) and trusted packages.
	Packages []PackageRule `json:"packages,omitempty"`
	// Secrets controls secrets committed in pull requests; nil = DefaultSecrets().
	Secrets *SecretsPreset `json:"secrets,omitempty"`
}

// SecretsPreset decides when secrets found in a pull request diff fail the check.
type SecretsPreset struct {
	Block          bool `json:"block"`           // keys, tokens and private keys fail the check (in block mode)
	BlockPasswords bool `json:"block_passwords"` // hard-coded passwords fail it too
}

// DefaultSecrets blocks keys, tokens and private keys; hard-coded passwords only warn.
func DefaultSecrets() SecretsPreset { return SecretsPreset{Block: true} }

// SecretsRules returns the secrets preset of a policy, defaults included.
func (pc PolicyConfig) SecretsRules() SecretsPreset {
	if pc.Presets == nil || pc.Presets.Secrets == nil {
		return DefaultSecrets()
	}
	return *pc.Presets.Secrets
}

// PackageRule constrains one package (or a glob of packages). A package
// matching several rules must satisfy all of them.
type PackageRule struct {
	Ecosystem string `json:"ecosystem,omitempty"` // npm, PyPI, Go, crates.io, Maven, ... ("" = any)
	Name      string `json:"name"`                // exact name or glob with * (e.g. @types/*), case-insensitive
	Versions  string `json:"versions,omitempty"`  // allowed range, e.g. ">=4.17.21 <5" or ">=1.2 || =0.9.3"; "" = any
	Deny      bool   `json:"deny,omitempty"`      // banned in every version
	Allow     bool   `json:"allow,omitempty"`     // trusted: no suspicious/license findings (vulnerabilities and malware still apply)
	Reason    string `json:"reason,omitempty"`
	Severity  string `json:"severity,omitempty"` // severity of a violation; default high (blocking)
}

// LicensePreset configures license compliance. Fields absent from the JSON
// default to Enabled=true, BlockingSeverity="high" (see Presets.UnmarshalJSON).
type LicensePreset struct {
	Deny             []string `json:"deny"`              // SPDX id prefixes (denied-license CEL rule)
	Enabled          bool     `json:"enabled"`           // project/usage-aware license checks (internal/license)
	BlockingSeverity string   `json:"blocking_severity"` // license findings at or above this severity block
}

// SuspiciousPreset toggles the suspicious-package rules (internal/suspicious
// and guarddog). Fields absent from the JSON take DefaultSuspicious values.
// A JSON "suspicious": null disables nothing: it means the defaults.
type SuspiciousPreset struct {
	Typosquat          bool     `json:"typosquat"`
	Unmaintained       bool     `json:"unmaintained"`
	UnmaintainedMonths int      `json:"unmaintained_months"`
	Deprecated         bool     `json:"deprecated"`
	NewPackage         bool     `json:"new_package"`
	NoSourceRepo       bool     `json:"no_source_repo"`
	UnusualBehaviour   bool     `json:"unusual_behaviour"`
	Blocking           []string `json:"blocking"` // rule names that fail the check: typosquat, unusual-behaviour, ...
}

// DefaultSuspicious reports everything but no-source-repo; only typosquat
// and unusual-behaviour (guarddog) block.
func DefaultSuspicious() SuspiciousPreset {
	return SuspiciousPreset{Typosquat: true, Unmaintained: true, UnmaintainedMonths: 24, Deprecated: true,
		NewPackage: true, UnusualBehaviour: true, Blocking: []string{"typosquat", "unusual-behaviour"}}
}

// UnmarshalJSON fills defaults for the license and suspicious presets so
// that keys missing from stored policies keep today's behaviour.
func (p *Presets) UnmarshalJSON(b []byte) error {
	type plain Presets
	sus := DefaultSuspicious()
	v := plain{License: LicensePreset{Enabled: true, BlockingSeverity: SeverityHigh}, Suspicious: &sus}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = Presets(v)
	return nil
}

// ParsePolicy decodes tenant_settings.policy; empty input is the zero config.
func ParsePolicy(raw []byte) (PolicyConfig, error) {
	var pc PolicyConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &pc); err != nil {
			return pc, fmt.Errorf("policy json: %w", err)
		}
	}
	return pc, nil
}

// CustomRule is a user-written CEL rule; Category is a lowercase name.
type CustomRule struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Summary  string `json:"summary"`
	Expr     string `json:"expr"`
}

var categoryNames = map[checks.CheckType]string{
	checks.CheckType_CheckTypeVulnerability:     "vulnerability",
	checks.CheckType_CheckTypeMalware:           "malware",
	checks.CheckType_CheckTypeLicense:           "license",
	checks.CheckType_CheckTypePopularity:        "popularity",
	checks.CheckType_CheckTypeMaintenance:       "maintenance",
	checks.CheckType_CheckTypeSecurityScorecard: "maintenance",
}

// CategoryName maps a vet check type to the policy_violations.category value.
func CategoryName(c checks.CheckType) string {
	if n, ok := categoryNames[c]; ok {
		return n
	}
	return "other"
}

func categoryFromName(n string) checks.CheckType {
	for c, name := range categoryNames {
		if name == strings.ToLower(n) {
			return c
		}
	}
	return checks.CheckType_CheckTypeOther
}

const notMal = `!v.id.startsWith("MAL-")`

// RulesFromPolicy converts tenant_settings.policy JSON into rules. An empty
// policy ({} or no presets and no custom rules) means DefaultRules().
func RulesFromPolicy(raw []byte) ([]Rule, error) {
	pc, err := ParsePolicy(raw)
	if err != nil {
		return nil, err
	}
	if pc.Presets == nil && len(pc.Custom) == 0 {
		return DefaultRules(), nil
	}
	var rules []Rule
	if p := pc.Presets; p != nil {
		if p.Malware.Enabled {
			rules = append(rules, DefaultRules()[0])
		}
		buckets := map[string][]string{
			"CRITICAL": {"critical"},
			"HIGH":     {"critical", "high"},
			"MEDIUM":   {"critical", "high", "medium"},
			"LOW":      {"critical", "high", "medium", "low"},
		}[strings.ToUpper(p.Vulnerability.MinRisk)]
		if len(buckets) > 0 {
			var parts []string
			for _, b := range buckets {
				parts = append(parts, fmt.Sprintf("vulns.%s.exists(v, %s)", b, notMal))
			}
			rules = append(rules, Rule{
				Name:     "vulnerability-" + strings.ToLower(p.Vulnerability.MinRisk) + "-or-higher",
				Category: checks.CheckType_CheckTypeVulnerability,
				Summary:  "Vulnerability with " + strings.ToUpper(p.Vulnerability.MinRisk) + " or higher risk",
				Expr:     strings.Join(parts, " || "),
			})
		}
		var deny []string
		for _, d := range p.License.Deny {
			if d = strings.TrimSpace(d); d != "" {
				deny = append(deny, "l.startsWith("+strconv.Quote(d)+")")
			}
		}
		if len(deny) > 0 {
			rules = append(rules, Rule{
				Name:     "denied-license",
				Category: checks.CheckType_CheckTypeLicense,
				Summary:  "License denied by policy",
				Expr:     "licenses.exists(l, " + strings.Join(deny, " || ") + ")",
			})
		}
		if p.Popularity.Enabled && p.Popularity.MinStars > 0 {
			// Packages without project data are not flagged.
			rules = append(rules, Rule{
				Name:     "low-popularity",
				Category: checks.CheckType_CheckTypePopularity,
				Summary:  fmt.Sprintf("Source repository has fewer than %d stars", p.Popularity.MinStars),
				Expr:     fmt.Sprintf("projects.size() > 0 && projects.all(p, p.stars < %d.0)", p.Popularity.MinStars),
			})
		}
		if p.Maintenance.Enabled && p.Maintenance.MinScorecard > 0 {
			// score 0 means "no scorecard data", which is not a finding.
			rules = append(rules, Rule{
				Name:     "low-scorecard",
				Category: checks.CheckType_CheckTypeMaintenance,
				Summary:  fmt.Sprintf("OpenSSF Scorecard below %.1f", p.Maintenance.MinScorecard),
				Expr:     fmt.Sprintf("scorecard.score > 0.0 && scorecard.score < %s", celFloat(p.Maintenance.MinScorecard)),
			})
		}
	}
	for _, c := range pc.Custom {
		if strings.TrimSpace(c.Expr) == "" {
			continue
		}
		rules = append(rules, Rule{Name: c.Name, Category: categoryFromName(c.Category), Summary: c.Summary, Expr: c.Expr})
	}
	return rules, nil
}

func celFloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}
