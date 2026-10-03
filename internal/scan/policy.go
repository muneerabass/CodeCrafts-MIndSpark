package scan

import (
	"fmt"

	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/pkg/analyzer/filter"
	"github.com/safedep/vet/pkg/models"
)

// Rule is one policy check, expressed in vet's CEL filter language.
type Rule struct {
	Name     string           `json:"name"`
	Category checks.CheckType `json:"category"`
	Summary  string           `json:"summary"`
	Expr     string           `json:"expr"`
}

// DefaultRules gate on malware and critical/high vulnerabilities, matching
// the product's default policy. License compliance is checked by
// internal/license (project- and usage-aware), not by a CEL rule.
func DefaultRules() []Rule {
	return []Rule{
		{
			Name:     "malicious-package",
			Category: checks.CheckType_CheckTypeMalware,
			Summary:  "Known malicious package",
			Expr:     `vulns.all.exists(v, v.id.startsWith("MAL-"))`,
		},
		{
			Name:     "critical-or-high-vulnerability",
			Category: checks.CheckType_CheckTypeVulnerability,
			Summary:  "Critical or high severity vulnerability",
			Expr:     `vulns.critical.exists(v, !v.id.startsWith("MAL-")) || vulns.high.exists(v, !v.id.startsWith("MAL-"))`,
		},
	}
}

// Violation is a rule that matched a package.
type Violation struct {
	Rule    Rule
	Package *models.Package
}

// Policy evaluates rules against packages. vet's evaluator stops at the first
// matching filter, so each rule gets its own evaluator to report all matches.
type Policy struct {
	rules []Rule
	evals []filter.Evaluator
}

// NewPolicy compiles rules; an invalid CEL expression is an error.
func NewPolicy(rules []Rule) (*Policy, error) {
	p := &Policy{rules: rules}
	for _, r := range rules {
		ev, err := filter.NewEvaluator(r.Name, filter.WithIgnoreError(true))
		if err != nil {
			return nil, err
		}
		f := &filtersuite.Filter{Name: r.Name, Value: r.Expr, CheckType: r.Category, Summary: r.Summary}
		if err := ev.AddFilter(f); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		p.evals = append(p.evals, ev)
	}
	return p, nil
}

// Evaluate returns every rule that matches pkg.
func (p *Policy) Evaluate(pkg *models.Package) ([]Violation, error) {
	var out []Violation
	for i, ev := range p.evals {
		res, err := ev.EvalPackage(pkg)
		if err != nil {
			return nil, fmt.Errorf("rule %q on %s@%s: %w", p.rules[i].Name, pkg.GetName(), pkg.GetVersion(), err)
		}
		if res.Matched() {
			out = append(out, Violation{Rule: p.rules[i], Package: pkg})
		}
	}
	return out, nil
}
