package render

import (
	"cmp"
	"encoding/json"
	"fmt"
	"html"
	"math"
	"sort"
	"strconv"
	"strings"
)

// PathNode is one package on an attack path.
type PathNode struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	ComponentID *string `json:"component_id"`
}

// PathItem is a ranked chain from the app to a risky package (CONTRACTS "PathItem").
// Chain runs from the direct dependency (depth 1) to the target, inclusive.
type PathItem struct {
	Chain       []PathNode `json:"chain"`
	Target      PathNode   `json:"target"`
	Advisories  []Vuln     `json:"advisories"`
	Risk        string     `json:"risk"`
	Score       int        `json:"score"`
	Depth       int        `json:"depth"`
	DirectHead  string     `json:"direct_head"`
	Imported    *bool      `json:"imported"`
	Dev         bool       `json:"dev"`
	Approximate bool       `json:"approximate"`
	Fix         string     `json:"fix"`
}

var riskWeight = map[string]float64{"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5}

var riskRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

func rankOf(risk string) int {
	if r, ok := riskRank[strings.ToUpper(risk)]; ok {
		return r
	}
	return 4
}

// Score is the path risk score (docs/RISK-MODEL.md): base by risk + 20·KEV +
// 20·EPSS, × imported (1 / unknown 0.6 / no 0.3) × dev 0.5 × depth decay;
// clamped 0–100. Malware scores 100.
func Score(risk string, kev bool, epss float64, imported *bool, dev bool, depth int, malware bool) int {
	if malware {
		return 100
	}
	s := riskWeight[strings.ToUpper(risk)] + 20*epss
	if kev {
		s += 20
	}
	switch {
	case imported == nil:
		s *= 0.6
	case !*imported:
		s *= 0.3
	}
	if dev {
		s *= 0.5
	}
	s *= math.Max(0.5, math.Min(1, 1-0.05*float64(depth-1)))
	return int(math.Round(math.Max(0, math.Min(100, s))))
}

// NewPath fills risk, score, depth, head and fix for a chain ending at target.
// sev is the fallback risk for targets without advisories (suspicious findings).
func NewPath(chain []PathNode, adv []Vuln, imported *bool, dev, approximate bool, sev, reason string) PathItem {
	p := PathItem{Chain: chain, Advisories: adv, Imported: imported, Dev: dev, Approximate: approximate, Depth: len(chain)}
	if p.Advisories == nil {
		p.Advisories = []Vuln{}
	}
	if len(chain) > 0 {
		p.Target = chain[len(chain)-1]
		p.DirectHead = chain[0].Name + "@" + chain[0].Version
	}
	if approximate && len(chain) == 1 {
		p.Depth = 0 // no graph: depth unknown
	}
	malware, kev, epss := false, false, 0.0
	p.Risk = strings.ToUpper(sev)
	sort.SliceStable(p.Advisories, func(i, j int) bool { return rankOf(p.Advisories[i].Risk) < rankOf(p.Advisories[j].Risk) })
	for _, a := range p.Advisories {
		malware = malware || strings.HasPrefix(a.ID, "MAL-")
		kev = kev || a.KEV
		epss = math.Max(epss, a.EPSS)
	}
	if len(p.Advisories) > 0 && rankOf(p.Advisories[0].Risk) < rankOf(p.Risk) {
		p.Risk = p.Advisories[0].Risk
	}
	if malware {
		p.Risk = "CRITICAL"
	}
	if _, ok := riskRank[p.Risk]; !ok {
		p.Risk = "LOW"
	}
	p.Score = Score(p.Risk, kev, epss, imported, dev, max(p.Depth, 1), malware)
	p.Fix = fixAdvice(p, malware, reason)
	return p
}

func fixAdvice(p PathItem, malware bool, reason string) string {
	t := p.Target.Name
	if malware {
		return fmt.Sprintf("Remove %s immediately and rotate any credentials it could access", t)
	}
	if len(p.Advisories) == 0 {
		if reason != "" {
			return "Review " + t + ": " + reason
		}
		return "Review " + t
	}
	// Recommend the highest fixed version so one upgrade clears every advisory.
	best, unfixed := "", 0
	for _, a := range p.Advisories {
		if a.FixedIn == "" {
			unfixed++
		} else if best == "" || compareVersions(a.FixedIn, best) > 0 {
			best = a.FixedIn
		}
	}
	fix := fmt.Sprintf("No fixed version of %s yet: replace it or mitigate", t)
	if best != "" {
		fix = fmt.Sprintf("Upgrade %s to ≥%s", t, best)
		if unfixed > 0 {
			fix += fmt.Sprintf("; %d advisory(ies) have no fix yet", unfixed)
		}
	}
	if p.Depth > 1 {
		head := p.Chain[0].Name
		fix += fmt.Sprintf(" (via %s: update %s or pin %s with an override/resolution)", head, head, t)
	}
	return fix
}

// ParseNameVersion splits "name@version" at the last @ (scoped npm names keep theirs).
func ParseNameVersion(s string) (string, string) {
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// Paths builds ranked attack paths from the report's packages: every malicious,
// vulnerable or suspicious package, along its stored chains (≤3).
func Paths(r Report) []PathItem {
	ids := map[string]*string{}
	for _, p := range r.Packages {
		if p.ID != "" {
			id := p.ID
			ids[p.Name+"@"+p.Version] = &id
		}
	}
	suspicious := map[string]Finding{}
	for _, f := range r.Findings {
		if f.Category == "suspicious" {
			if old, ok := suspicious[f.Package]; !ok || rankOf(f.Severity) < rankOf(old.Severity) {
				suspicious[f.Package] = f
			}
		}
	}
	var out []PathItem
	seen := map[string]bool{}
	for _, p := range r.Packages {
		key := p.Name + "@" + p.Version
		sf, isSusp := suspicious[key]
		if (!p.Malware && len(p.Vulns) == 0 && !isSusp) || seen[key] {
			continue
		}
		seen[key] = true // same package in several manifests: one set of paths
		chains := p.Paths
		if len(chains) == 0 && len(p.Via) > 0 {
			chains = [][]string{p.Via}
		}
		approx := p.GraphSource == "depsdev"
		if len(chains) == 0 {
			chains, approx = [][]string{{key}}, p.Direct == nil || !*p.Direct
		}
		for _, c := range chains {
			nodes := make([]PathNode, len(c))
			for i, nv := range c {
				n, v := ParseNameVersion(nv)
				nodes[i] = PathNode{Name: n, Version: v, ComponentID: ids[nv]}
			}
			out = append(out, NewPath(nodes, append([]Vuln(nil), p.Vulns...), p.Imported, p.Dev, approx, sf.Severity, sf.Summary))
		}
	}
	SortPaths(out)
	return out
}

// SortPaths orders by score desc, then risk, depth and target name.
func SortPaths(ps []PathItem) {
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if rankOf(a.Risk) != rankOf(b.Risk) {
			return rankOf(a.Risk) < rankOf(b.Risk)
		}
		if a.Depth != b.Depth {
			return a.Depth < b.Depth
		}
		return a.Target.Name+a.Target.Version < b.Target.Name+b.Target.Version
	})
}

// Counts summarises a report.
type Counts struct {
	Packages        int `json:"packages"`
	Direct          int `json:"direct"`
	Transitive      int `json:"transitive"`
	Vulnerabilities int `json:"vulnerabilities"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	TransitiveVulns int `json:"transitive_vulnerabilities"`
	Malicious       int `json:"malicious"`
	Suspicious      int `json:"suspicious"`
	LicenseIssues   int `json:"license_issues"`
	AttackPaths     int `json:"attack_paths"`
	Blocking        int `json:"blocking"`
}

// FullData is the structured combined report (format=json).
type FullData struct {
	ScanID     string      `json:"scan_id"`
	URL        string      `json:"url"`
	Project    Project     `json:"project"`
	Version    string      `json:"version"`
	Date       string      `json:"date"`
	Verdict    string      `json:"verdict"` // pass | fail
	Counts     Counts      `json:"counts"`
	Packages   []Package   `json:"packages"`
	Violations []Violation `json:"violations"`
	Findings   []Finding   `json:"findings"`
	Paths      []PathItem  `json:"paths"`
	NextSteps  []string    `json:"next_steps"`
}

func nonMal(vs []Vuln) []Vuln {
	var out []Vuln
	for _, v := range vs {
		if !strings.HasPrefix(v.ID, "MAL-") {
			out = append(out, v)
		}
	}
	return out
}

// Data computes the structured combined report.
func Data(r Report) FullData {
	d := FullData{ScanID: r.ScanID, URL: r.scanURL(), Project: r.Project, Version: r.Version, Date: r.Date,
		Packages: r.Packages, Violations: r.Violations, Findings: r.Findings, Paths: Paths(r)}
	if d.Packages == nil {
		d.Packages = []Package{}
	}
	if d.Violations == nil {
		d.Violations = []Violation{}
	}
	if d.Findings == nil {
		d.Findings = []Finding{}
	}
	if d.Paths == nil {
		d.Paths = []PathItem{}
	}
	c := &d.Counts
	c.Packages = len(r.Packages)
	for _, p := range r.Packages {
		if p.Direct != nil && *p.Direct {
			c.Direct++
		} else if p.Direct != nil {
			c.Transitive++
		}
		if p.Malware {
			c.Malicious++
		}
		for _, v := range nonMal(p.Vulns) {
			c.Vulnerabilities++
			switch strings.ToUpper(v.Risk) {
			case "CRITICAL":
				c.Critical++
			case "HIGH":
				c.High++
			case "MEDIUM":
				c.Medium++
			case "LOW":
				c.Low++
			}
			if p.Direct != nil && !*p.Direct {
				c.TransitiveVulns++
			}
		}
	}
	c.Blocking = len(r.Violations)
	for _, f := range r.Findings {
		if f.Category == "suspicious" {
			c.Suspicious++
		} else if f.Category == "license" {
			c.LicenseIssues++
		}
		if f.Blocking {
			c.Blocking++
		}
	}
	c.AttackPaths = len(d.Paths)
	d.Verdict = "pass"
	if c.Blocking > 0 || c.Malicious > 0 {
		d.Verdict = "fail"
	}
	d.NextSteps = nextSteps(r, d)
	return d
}

func nextSteps(r Report, d FullData) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, p := range r.Packages {
		if p.Malware {
			add(fmt.Sprintf("Remove %s@%s immediately and rotate any credentials it could access.", p.Name, p.Version))
		}
	}
	n := 0
	for _, p := range d.Paths {
		if len(p.Advisories) > 0 && !strings.HasPrefix(p.Fix, "Remove") && n < 5 && !seen[p.Fix+"."] {
			add(p.Fix + ".")
			n++
		}
	}
	for _, f := range r.Findings {
		switch f.Rule {
		case "typosquat":
			if s, ok := f.Details["similar_to"].(string); ok && s != "" {
				add(fmt.Sprintf("Confirm %s is intended; it looks like %s. Remove it if it was a typo.", f.Package, s))
			} else {
				add(fmt.Sprintf("Confirm %s is intended; its name looks like a popular package.", f.Package))
			}
		case "deprecated", "unmaintained":
			add(fmt.Sprintf("Plan a replacement for %s (%s).", f.Package, f.Rule))
		case "unusual-behaviour":
			add(fmt.Sprintf("Review the install-time behaviour of %s before the next release.", f.Package))
		}
	}
	if d.Counts.LicenseIssues > 0 {
		add("Review the license issues with whoever approves licenses; set the project license and usage model in depguard if they are wrong.")
	}
	if len(out) == 0 {
		add("No action needed. Keep scanning on every pull request.")
	}
	return out
}

// ----------------------------------------------------------- full report

// block is a format-neutral piece of the full report.
type block struct {
	heading int // 2 or 3 for headings; 0 otherwise
	text    string
	head    []string
	rows    [][]string
	items   []string
}

const maxReportRows = 200 // per table; the JSON report has everything

func table(head []string, rows [][]string) block {
	if len(rows) == 0 {
		return block{text: "None found."}
	}
	b := block{head: head, rows: rows}
	if len(rows) > maxReportRows {
		b.rows = rows[:maxReportRows]
		b.items = []string{fmt.Sprintf("%d more rows not shown; download the JSON report for all of them.", len(rows)-maxReportRows)}
	}
	return b
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func triState(b *bool) string {
	if b == nil {
		return "unknown"
	}
	return yesNo(*b)
}

func epssText(e float64) string {
	if e == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", e*100)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func chainText(c []PathNode) string {
	parts := []string{"app"}
	for _, n := range c {
		parts = append(parts, n.Name+"@"+n.Version)
	}
	return strings.Join(parts, " → ")
}

var usageNames = map[string]string{
	"internal": "internal use only", "saas": "SaaS (network service)",
	"distributed_binary": "distributed as a binary", "distributed_source": "distributed as source",
}

func blocks(r Report, d FullData) []block {
	c := d.Counts
	title := "depguard dependency risk report"
	if r.Project.Name != "" {
		title += ": " + r.Project.Name
	}
	meta := []string{}
	if r.Version != "" {
		meta = append(meta, "Version: "+r.Version)
	}
	if r.Date != "" {
		meta = append(meta, "Scanned: "+r.Date)
	}
	meta = append(meta, "Scan: "+d.URL)
	verdict := "PASS: no blocking issues."
	if d.Verdict == "fail" {
		verdict = fmt.Sprintf("FAIL: %d blocking issue(s)", c.Blocking)
		if c.Malicious > 0 {
			verdict += fmt.Sprintf(", %d malicious package(s)", c.Malicious)
		}
		verdict += "."
	}
	bs := []block{{heading: 1, text: title}, {text: strings.Join(meta, " · ")},
		{heading: 2, text: "1. Summary"}, {text: "Verdict: " + verdict},
		{head: []string{"Measure", "Count"}, rows: [][]string{
			{"Packages scanned", fmt.Sprint(c.Packages)},
			{"Direct / transitive", fmt.Sprintf("%d / %d", c.Direct, c.Transitive)},
			{"Vulnerabilities (critical / high / medium / low)", fmt.Sprintf("%d (%d / %d / %d / %d)", c.Vulnerabilities, c.Critical, c.High, c.Medium, c.Low)},
			{"Transitive vulnerabilities", fmt.Sprint(c.TransitiveVulns)},
			{"Malicious packages", fmt.Sprint(c.Malicious)},
			{"Suspicious findings", fmt.Sprint(c.Suspicious)},
			{"License issues", fmt.Sprint(c.LicenseIssues)},
			{"Attack paths", fmt.Sprint(c.AttackPaths)},
		}}}

	// 2. Vulnerabilities by severity.
	bs = append(bs, block{heading: 2, text: "2. Vulnerabilities by severity"})
	type pv struct {
		p Package
		v Vuln
	}
	var all []pv
	for _, p := range r.Packages {
		for _, v := range nonMal(p.Vulns) {
			all = append(all, pv{p, v})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return rankOf(all[i].v.Risk) < rankOf(all[j].v.Risk) })
	if len(all) == 0 {
		bs = append(bs, block{text: "No known vulnerabilities."})
	}
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		var rows [][]string
		for _, x := range all {
			risk := strings.ToUpper(x.v.Risk)
			if _, known := riskRank[risk]; !known {
				risk = "UNKNOWN"
			}
			if risk == sev {
				rows = append(rows, []string{x.p.Name, x.p.Version, depLabel(x.p), x.v.ID, risk, epssText(x.v.EPSS), yesNo(x.v.KEV), orDash(x.v.FixedIn)})
			}
		}
		if len(rows) > 0 {
			bs = append(bs, block{heading: 3, text: fmt.Sprintf("%s (%d)", strings.ToUpper(sev[:1])+strings.ToLower(sev[1:]), len(rows))},
				table([]string{"Package", "Version", "Dependency", "Advisory", "Risk", "EPSS", "KEV", "Fixed in"}, rows))
		}
	}

	// 3. Transitive vulnerabilities.
	bs = append(bs, block{heading: 2, text: "3. Transitive vulnerabilities"},
		block{text: "Vulnerable packages you do not depend on directly, with how they reach your app."})
	var trows [][]string
	for _, p := range r.Packages {
		vs := nonMal(p.Vulns)
		if p.Direct == nil || *p.Direct || len(vs) == 0 {
			continue
		}
		var ids []string
		for _, v := range vs {
			ids = append(ids, v.ID+" ("+v.Risk+")")
		}
		via := "unknown"
		if len(p.Via) > 0 {
			via = strings.Join(append([]string{"app"}, p.Via...), " → ")
		}
		trows = append(trows, []string{p.Name + "@" + p.Version, orDash(fmt.Sprint(p.Depth)), strings.Join(ids, ", "), via})
	}
	bs = append(bs, table([]string{"Package", "Depth", "Advisories", "Introduced via"}, trows))

	// 4. Suspicious packages.
	bs = append(bs, block{heading: 2, text: "4. Suspicious packages"},
		block{text: "Known malware, lookalike (typosquat) names, unmaintained, deprecated or brand-new packages and unusual install-time behaviour."})
	var srows [][]string
	for _, p := range r.Packages {
		if p.Malware {
			var ids []string
			for _, v := range p.Vulns {
				if strings.HasPrefix(v.ID, "MAL-") {
					ids = append(ids, v.ID)
				}
			}
			srows = append(srows, []string{"malware", "critical", p.Name + "@" + p.Version, "Known malicious package " + strings.Join(ids, ", ")})
		}
	}
	for _, f := range sortedFindings(r.Findings, "suspicious") {
		reason := f.Summary
		if s, ok := f.Details["similar_to"].(string); ok && s != "" {
			reason += " (looks like " + s + ")"
		}
		if s, ok := f.Details["reason"].(string); ok && s != "" && !strings.Contains(reason, s) {
			reason += ": " + s
		}
		srows = append(srows, []string{f.Rule, f.Severity, f.Package, reason})
	}
	bs = append(bs, table([]string{"Rule", "Severity", "Package", "Why"}, srows))

	// 5. License issues.
	lic := r.Project.License
	if lic == "" {
		lic = "unknown"
	}
	if r.Project.LicenseSource != "" {
		lic += " (" + r.Project.LicenseSource + ")"
	}
	usage := usageNames[r.Project.UsageModel]
	if usage == "" {
		usage = orDash(r.Project.UsageModel)
	}
	bs = append(bs, block{heading: 2, text: "5. License issues"},
		block{text: "Project license: " + lic + " · Usage model: " + usage})
	var lrows [][]string
	var conflicts []string
	for _, f := range sortedFindings(r.Findings, "license") {
		l, _ := f.Details["license"].(string)
		lrows = append(lrows, []string{f.Rule, f.Severity, f.Package, orDash(l), f.Summary})
		if f.Rule == "license-conflict" || f.Rule == "license-incompatible" {
			conflicts = append(conflicts, f.Package+": "+f.Summary)
		}
	}
	bs = append(bs, table([]string{"Rule", "Severity", "Package", "License", "Explanation"}, lrows))
	if len(conflicts) > 0 {
		bs = append(bs, block{heading: 3, text: "Conflicts"}, block{items: conflicts})
	}

	// 6. Attack paths.
	bs = append(bs, block{heading: 2, text: "6. Attack paths"},
		block{text: "Chains from your app to a risky package, highest score first. Score 0-100 combines severity, KEV, EPSS, whether your code imports the chain's direct dependency, dev-only use and depth."})
	var prows [][]string
	for i, p := range d.Paths {
		chain := chainText(p.Chain)
		if p.Approximate {
			chain += " (approximate)"
		}
		prows = append(prows, []string{fmt.Sprint(i + 1), fmt.Sprint(p.Score), p.Risk, chain, triState(p.Imported), p.Fix})
	}
	bs = append(bs, table([]string{"#", "Score", "Risk", "Chain", "Imported", "Fix"}, prows))

	// 7. Next steps.
	bs = append(bs, block{heading: 2, text: "7. Recommended next steps"}, block{items: d.NextSteps, heading: -1})
	return bs
}

func sortedFindings(fs []Finding, category string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Category == category {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return rankOf(out[i].Severity) < rankOf(out[j].Severity) })
	return out
}

// Full renders the combined report as md, html or json.
func Full(r Report, format string) (string, error) {
	d := Data(r)
	switch format {
	case "json":
		b, err := json.MarshalIndent(d, "", "  ")
		return string(b), err
	case "md", "":
		return fullMD(blocks(r, d)), nil
	case "html":
		return fullHTML(r, blocks(r, d)), nil
	}
	return "", fmt.Errorf("unknown report format %q", format)
}

var cellEscaper = strings.NewReplacer(`\`, `\\`, "|", `\|`, "<", "&lt;", ">", "&gt;", "`", "\\`", "*", `\*`, "_", `\_`,
	"[", `\[`, "]", `\]`, "\r", " ", "\n", " ")

func fullMD(bs []block) string {
	var b strings.Builder
	for _, x := range bs {
		switch {
		case x.heading > 0:
			b.WriteString(strings.Repeat("#", x.heading) + " " + cellEscaper.Replace(x.text) + "\n\n")
		case len(x.head) > 0:
			b.WriteString("| " + strings.Join(x.head, " | ") + " |\n|" + strings.Repeat("---|", len(x.head)) + "\n")
			for _, row := range x.rows {
				cells := make([]string, len(row))
				for i, c := range row {
					cells[i] = cellEscaper.Replace(c)
				}
				b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
			}
			b.WriteString("\n")
		case x.text != "":
			b.WriteString(cellEscaper.Replace(x.text) + "\n\n")
		}
		if len(x.items) > 0 {
			for i, it := range x.items {
				if x.heading == -1 {
					fmt.Fprintf(&b, "%d. %s\n", i+1, cellEscaper.Replace(it))
				} else {
					b.WriteString("- " + cellEscaper.Replace(it) + "\n")
				}
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("Generated by depguard\n")
	return b.String()
}

const reportCSS = `:root{--fg:#1f2937;--muted:#6b7280;--line:#e5e7eb;--brand:#4f46e5}
*{box-sizing:border-box}body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:#fff;margin:0;padding:32px;max-width:1100px}
h1{font-size:22px;color:var(--brand);margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;padding-bottom:4px;border-bottom:2px solid var(--brand)}
h3{font-size:14px;margin:16px 0 6px}p{margin:6px 0}.meta{color:var(--muted);font-size:12px}
table{border-collapse:collapse;width:100%;margin:8px 0 12px;font-size:12px}th,td{border:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#eef2ff}.sev{display:inline-block;padding:0 6px;border-radius:8px;font-weight:600;font-size:11px;color:#fff}
.sev-critical{background:#b91c1c}.sev-high{background:#ea580c}.sev-medium{background:#ca8a04}.sev-low{background:#2563eb}.sev-info,.sev-unknown{background:#6b7280}
footer{margin-top:32px;color:var(--muted);font-size:11px}
@media print{body{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}`

var sevClass = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true, "unknown": true}

func fullHTML(r Report, bs []block) string {
	var b strings.Builder
	title := "depguard report"
	if r.Project.Name != "" {
		title += ": " + r.Project.Name
	}
	b.WriteString("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>" + html.EscapeString(title) + "</title>\n<style>" + reportCSS + "</style></head><body>\n")
	for i, x := range bs {
		switch {
		case x.heading > 0:
			fmt.Fprintf(&b, "<h%d>%s</h%d>\n", x.heading, html.EscapeString(x.text), x.heading)
		case len(x.head) > 0:
			b.WriteString("<table><thead><tr>")
			for _, h := range x.head {
				b.WriteString("<th>" + html.EscapeString(h) + "</th>")
			}
			b.WriteString("</tr></thead><tbody>\n")
			for _, row := range x.rows {
				b.WriteString("<tr>")
				for _, c := range row {
					if sevClass[strings.ToLower(c)] {
						fmt.Fprintf(&b, `<td><span class="sev sev-%s">%s</span></td>`, strings.ToLower(c), html.EscapeString(c))
					} else {
						b.WriteString("<td>" + html.EscapeString(c) + "</td>")
					}
				}
				b.WriteString("</tr>\n")
			}
			b.WriteString("</tbody></table>\n")
		case x.text != "":
			cls := ""
			if i == 1 {
				cls = ` class="meta"`
			}
			b.WriteString("<p" + cls + ">" + html.EscapeString(x.text) + "</p>\n")
		}
		if len(x.items) > 0 {
			tag := "ul"
			if x.heading == -1 {
				tag = "ol"
			}
			b.WriteString("<" + tag + ">")
			for _, it := range x.items {
				b.WriteString("<li>" + html.EscapeString(it) + "</li>")
			}
			b.WriteString("</" + tag + ">\n")
		}
	}
	b.WriteString("<footer>Generated by depguard</footer>\n</body></html>\n")
	return b.String()
}

// compareVersions orders dotted versions by their numeric segments, then
// lexically (good enough to pick the highest OSV fixed version across ecosystems).
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil && xn != yn:
			return cmp.Compare(xn, yn)
		case (xerr != nil || yerr != nil) && x != y:
			if x == "" { // 1.0 < 1.0.1
				return -1
			}
			if y == "" {
				return 1
			}
			return strings.Compare(x, y)
		}
	}
	return 0
}

func versionParts(v string) []string {
	return strings.FieldsFunc(strings.TrimPrefix(v, "v"), func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '_' })
}
