package license

import (
	"context"
	"fmt"
	"strings"

	"github.com/depguard/depguard/internal/scan"
	"github.com/safedep/vet/pkg/models"
)

// Rule names.
const (
	RuleUnknown             = "license-unknown"
	RuleNetworkCopyleft     = "license-network-copyleft"
	RuleCopyleftDistributed = "license-copyleft-distributed"
	RuleWeakCopyleft        = "license-weak-copyleft"
	RuleNoncommercial       = "license-noncommercial"
	RuleIncompatible        = "license-incompatible"
	RuleConflict            = "license-conflict"
	RuleDenied              = "license-denied"
)

const maxConflicts = 50

// Config tunes the license checker (policy preset "license").
type Config struct {
	Deny             []string // extra denied SPDX prefixes from policy (rule license-denied)
	BlockingSeverity string   // findings at or above this severity block; default high
}

// New returns the license compliance checker.
func New(cfg Config) scan.Checker { return checker{cfg} }

type checker struct{ cfg Config }

func (checker) Name() string { return "license" }

var sevRank = map[string]int{scan.SeverityInfo: 0, scan.SeverityLow: 1, scan.SeverityMedium: 2, scan.SeverityHigh: 3, scan.SeverityCritical: 4}

var usageWords = map[string]string{
	scan.UsageInternal: "internal-only", scan.UsageSaaS: "SaaS",
	scan.UsageDistributedBinary: "distributed binary", scan.UsageDistributedSource: "distributed source",
}

// staticEcosystems link dependencies statically, so LGPL relinking is hard.
var staticEcosystems = map[string]bool{models.EcosystemGo: true, models.EcosystemCargo: true}

func (c checker) Check(_ context.Context, in scan.CheckInput) ([]scan.Finding, error) {
	usage := in.Project.UsageModel
	if usageWords[usage] == "" {
		usage = scan.UsageDistributedBinary
	}
	distributed := usage == scan.UsageDistributedBinary || usage == scan.UsageDistributedSource
	project := parse(in.Project.License)
	projKnown := project.known()
	projName := project.String()
	if !projKnown {
		projName = "unknown"
	}
	projCopyleft := projKnown && rank[pick(project, func(a alt) int { return rank[a.worst()] }).worst()] >= rank[CatWeakCopyleft]
	block, ok := sevRank[strings.ToLower(c.cfg.BlockingSeverity)]
	if !ok {
		block = sevRank[scan.SeverityHigh]
	}
	denied := func(t term) bool {
		id := strings.ToLower(t.String())
		for _, p := range c.cfg.Deny {
			if p = strings.ToLower(strings.TrimSpace(p)); p != "" && strings.HasPrefix(id, p) {
				return true
			}
		}
		return false
	}
	compatible := func(t term) (string, bool) {
		v := projectVerdict(project, t)
		return v, projKnown && v != "" && verdictRank[v] == 0
	}
	// OR: least restrictive choice; a choice the project can't include
	// (distributed) or that policy denies is avoided first.
	score := func(a alt) int {
		s := 10 * rank[a.worst()]
		for _, t := range a {
			if denied(t) {
				s += 1000
			}
			if distributed && projKnown && projectVerdict(project, t) == "No" {
				s += 100
			}
		}
		return s
	}

	var out []scan.Finding
	var shipped []chosen
	for _, p := range in.Packages {
		dev := in.Context[p].Dev
		d := parseList(scan.Licenses(p))
		a := pick(d, score)
		if !dev {
			shipped = append(shipped, chosen{p, a})
		}
		byRule := map[string]scan.Finding{}
		var order []string
		add := func(rule, sev string, t term, summary string, extra map[string]any) {
			if dev && rule != RuleDenied {
				sev = scan.SeverityInfo
				summary += " It is a dev-only dependency, so it is not shipped."
			}
			if old, ok := byRule[rule]; ok && sevRank[old.Severity] >= sevRank[sev] {
				return
			}
			details := map[string]any{"license": t.String(), "category": t.category(),
				"project_license": projName, "usage_model": usage}
			if e := d.String(); e != t.String() {
				details["expression"] = e
			}
			for k, v := range extra {
				details[k] = v
			}
			if _, ok := byRule[rule]; !ok {
				order = append(order, rule)
			}
			byRule[rule] = scan.Finding{Rule: rule, Category: scan.CategoryLicense, Severity: sev,
				Blocking: sevRank[sev] >= block, Summary: summary, Details: details, Package: p}
		}
		name := p.GetName()
		for _, t := range a {
			lic := t.String()
			if denied(t) {
				add(RuleDenied, scan.SeverityHigh, t, fmt.Sprintf("%s is licensed %s, which is on your organisation's denied license list.", name, lic), nil)
			}
			switch t.category() {
			case CatUnknown:
				sev := scan.SeverityMedium
				if distributed {
					sev = scan.SeverityHigh
				}
				add(RuleUnknown, sev, t, fmt.Sprintf("%s has no recognised license (%s); until it is clarified you have no clear right to use or redistribute it.", name, lic), nil)
			case CatNetworkCopyleft:
				v, ok := compatible(t)
				switch {
				case usage == scan.UsageInternal:
					add(RuleNetworkCopyleft, scan.SeverityInfo, t, fmt.Sprintf("%s (%s) is network copyleft, but internal-only use triggers no obligations.", name, lic), nil)
				case ok:
					add(RuleNetworkCopyleft, scan.SeverityInfo, t, fmt.Sprintf("%s (%s) is compatible with your %s project; your users must be offered the complete source.", name, lic, projName), map[string]any{"osadl": v})
				default:
					add(RuleNetworkCopyleft, scan.SeverityHigh, t, fmt.Sprintf("%s requires releasing your complete source even when users only reach the app over a network; your project is %s.", lic, projName), osadlDetail(v))
				}
			case CatStrongCopyleft:
				v, ok := compatible(t)
				switch {
				case !distributed:
					add(RuleCopyleftDistributed, scan.SeverityInfo, t, fmt.Sprintf("%s (%s) only requires releasing source when you distribute the app; %s use has no copyleft obligations.", name, lic, usageWords[usage]), nil)
				case ok:
					add(RuleCopyleftDistributed, scan.SeverityInfo, t, fmt.Sprintf("%s (%s) is compatible with your %s project; ship the complete source of the combined work.", name, lic, projName), map[string]any{"osadl": v})
				default:
					add(RuleCopyleftDistributed, scan.SeverityHigh, t, fmt.Sprintf("%s requires releasing your source when you distribute this app; your project is %s.", lic, projName), osadlDetail(v))
				}
			case CatWeakCopyleft:
				lgpl := strings.HasPrefix(t.ID, "LGPL") || (t.Exc != "" && classify(t.ID) == CatStrongCopyleft)
				eco := string(p.Ecosystem)
				if eco == "" && p.Manifest != nil {
					eco = p.Manifest.Ecosystem
				}
				switch {
				case lgpl && usage == scan.UsageDistributedBinary && staticEcosystems[eco]:
					add(RuleWeakCopyleft, scan.SeverityHigh, t, fmt.Sprintf("%s (%s) is statically linked in %s builds, so users must be able to relink your app: ship object files or your source.", name, lic, eco), map[string]any{"static_linking": true})
				case lgpl && usage == scan.UsageDistributedBinary:
					add(RuleWeakCopyleft, scan.SeverityMedium, t, fmt.Sprintf("%s (%s) lets your code stay closed only if the library stays replaceable (dynamic linking); ship its source and license.", name, lic), nil)
				case distributed:
					add(RuleWeakCopyleft, scan.SeverityLow, t, fmt.Sprintf("%s (%s): share changes to this package's own files and keep its license notice; your code may stay closed.", name, lic), nil)
				}
			case CatNoncommercial:
				sev := scan.SeverityHigh
				if usage == scan.UsageInternal {
					sev = scan.SeverityMedium
				}
				add(RuleNoncommercial, sev, t, fmt.Sprintf("%s (%s) restricts commercial use, hosting or derivatives; get a commercial license or replace it.", name, lic), nil)
			default: // unencumbered, permissive, other
			}
			// Project ↔ dependency compatibility (OSADL) for licenses the category
			// rules above don't already judge: permissive deps always, weak
			// copyleft only under a copyleft project (a permissive project
			// "including" LGPL/MPL is OSADL "No" but is the weak-copyleft rule's job).
			if cat := t.category(); distributed && projKnown && (rank[cat] <= rank[CatOther] || (cat == CatWeakCopyleft && projCopyleft)) {
				switch v := projectVerdict(project, t); v {
				case "No":
					add(RuleIncompatible, scan.SeverityHigh, t, fmt.Sprintf("%s (%s) cannot be included in a %s-licensed project you distribute.", name, lic, projName), map[string]any{"osadl": v})
				case "Check dependency", "Unknown":
					add(RuleIncompatible, scan.SeverityLow, t, fmt.Sprintf("Whether %s (%s) may be included in your %s project depends on how they are combined (OSADL: %s); review it.", name, lic, projName, v), map[string]any{"osadl": v})
				}
			}
		}
		for _, r := range order {
			out = append(out, byRule[r])
		}
	}
	if distributed {
		out = append(out, conflictFindings(shipped, usage, projName, block)...)
	}
	return out, nil
}

// chosen is a shipped package with the license alternative picked for it.
type chosen struct {
	p *models.Package
	a alt
}

func osadlDetail(v string) map[string]any {
	if v == "" {
		return nil
	}
	return map[string]any{"osadl": v}
}

// conflictFindings reports dependency pairs whose licenses cannot coexist in
// one distributed work, once per package pair, at most maxConflicts.
func conflictFindings(shipped []chosen, usage, projName string, block int) []scan.Finding {
	memo := map[[2]string][2]term{}
	clash := func(a, b alt) (term, term, bool) {
		k := [2]string{a.String(), b.String()}
		if r, ok := memo[k]; ok {
			return r[0], r[1], r[0] != term{}
		}
		for _, x := range a {
			for _, y := range b {
				if conflicts(x, y) {
					memo[k] = [2]term{x, y}
					return x, y, true
				}
			}
		}
		memo[k] = [2]term{}
		return term{}, term{}, false
	}
	var out []scan.Finding
	seen := map[[2]string]bool{}
	id := func(p *models.Package) string { return p.GetName() + "@" + p.GetVersion() }
	for i, x := range shipped {
		for _, y := range shipped[i+1:] {
			k := [2]string{id(x.p), id(y.p)}
			if k[0] == k[1] || seen[k] || seen[[2]string{k[1], k[0]}] {
				continue
			}
			tx, ty, ok := clash(x.a, y.a)
			if !ok {
				continue
			}
			seen[k] = true
			out = append(out, scan.Finding{Rule: RuleConflict, Category: scan.CategoryLicense,
				Severity: scan.SeverityHigh, Blocking: sevRank[scan.SeverityHigh] >= block, Package: x.p,
				Summary: fmt.Sprintf("%s (%s) and %s (%s) cannot be combined in one distributed work: their licenses are incompatible.",
					x.p.GetName(), tx, y.p.GetName(), ty),
				Details: map[string]any{"license": tx.String(), "category": tx.category(), "project_license": projName,
					"usage_model": usage, "other": k[1], "other_license": ty.String()}})
			if len(out) == maxConflicts {
				return out
			}
		}
	}
	return out
}
