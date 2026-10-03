// Package render produces the PR comment and Check Run text for a scan.
// Pure functions: no I/O. All repo-derived text is escaped.
package render

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Marker identifies our sticky PR comment.
const Marker = "<!-- depguard:pr-report -->"

// MaxLen is GitHub's limit for comment bodies and check-run summaries.
const MaxLen = 65536

type Vuln struct {
	ID      string  `json:"id"`
	Risk    string  `json:"risk"`
	Summary string  `json:"summary,omitempty"`
	EPSS    float64 `json:"epss"`
	KEV     bool    `json:"kev"`
	FixedIn string  `json:"fixed_in"`
}

type Package struct {
	ID           string `json:"component_id,omitempty"` // component id, when known
	Name         string `json:"name"`
	Version      string `json:"version"`
	Ecosystem    string `json:"ecosystem"`
	ManifestPath string `json:"manifest_path"`
	Malware      bool   `json:"malware"`
	Vulnerable   bool   `json:"vulnerable"`
	RiskyLicense bool   `json:"risky_license"`

	// Dependency-graph context (see docs/CONTRACTS.md "Risk analysis").
	Direct      *bool      `json:"direct"` // nil = unknown
	Depth       int        `json:"depth"`  // 1 = direct, 0 = unknown
	Dev         bool       `json:"dev"`
	Via         []string   `json:"via"`   // shortest chain root→pkg, "name@version", last = pkg
	Paths       [][]string `json:"paths"` // ≤3 chains like Via
	Imported    *bool      `json:"imported"`
	GraphSource string     `json:"graph_source"` // lockfile | depsdev | none
	Licenses    []string   `json:"licenses"`
	Vulns       []Vuln     `json:"vulns"` // all advisories (for the full report)
}

type Violation struct {
	Rule     string  `json:"rule"`
	Category string  `json:"category"`
	Summary  string  `json:"summary"`
	Package  Package `json:"package"`
	Vulns    []Vuln  `json:"vulns"` // top few, highest risk first
}

// Finding is a suspicious-package or license finding (policy_violations row
// with category suspicious|license).
type Finding struct {
	Rule         string         `json:"rule"`
	Category     string         `json:"category"`
	Severity     string         `json:"severity"`
	Blocking     bool           `json:"blocking"`
	Summary      string         `json:"summary"`
	Package      string         `json:"package"` // name@version
	ManifestPath string         `json:"manifest_path"`
	Details      map[string]any `json:"details"`
}

// Project is the scanned project's license context.
type Project struct {
	Name          string `json:"name"`
	License       string `json:"license"`
	LicenseSource string `json:"license_source"`
	UsageModel    string `json:"usage_model"`
}

// Report is everything the renderers need.
type Report struct {
	PublicURL  string // web app base URL
	ScanID     string
	Packages   []Package
	Violations []Violation
	Findings   []Finding
	Project    Project
	Version    string   // branch/version name (full report header)
	Date       string   // preformatted scan date (full report header)
	AIUsage    []string // e.g. "Anthropic API - AI client in app.py:8"
	NoChanges  bool     // PR touched no dependency manifests
}

func (r Report) scanURL() string {
	return strings.TrimRight(r.PublicURL, "/") + "/scans/" + r.ScanID
}

func (r Report) any(f func(Package) bool) bool {
	for _, p := range r.Packages {
		if f(p) {
			return true
		}
	}
	return false
}

// Clean reports no violations and no flagged packages.
func (r Report) Clean() bool {
	return len(r.Violations) == 0 && len(r.Findings) == 0 && !r.any(func(p Package) bool { return p.Malware || p.Vulnerable || p.RiskyLicense })
}

var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "{", `\{`, "}", `\}`, "[", `\[`, "]", `\]`,
	"<", "&lt;", ">", "&gt;", "(", `\(`, ")", `\)`, "#", `\#`, "!", `\!`, "|", `\|`, "~", `\~`,
	"\r", " ", "\n", " ",
	// Zero-width joiner after @ prevents @mentions and team pings.
	"@", "@‍",
)

// Escape makes untrusted text (package names, paths) inert in GitHub markdown.
func Escape(s string) string { return mdEscaper.Replace(s) }

func badge(label string, fail bool) string {
	status, color := "Pass", "2ea44f"
	if fail {
		status, color = "Fail", "d73a49"
	}
	return fmt.Sprintf("![%s %s](https://img.shields.io/badge/%s-%s-%s)", label, status, label, status, color)
}

func mark(bad bool) string {
	if bad {
		return "❌"
	}
	return "✅"
}

func fixHint(category string) string {
	switch category {
	case "malware":
		return "Remove this package immediately and rotate any credentials it could have accessed."
	case "vulnerability":
		return "Upgrade to a version that fixes the listed advisories."
	case "license":
		return "Replace the package or get the license approved."
	default:
		return "Review the package against your policy."
	}
}

// Comment renders the sticky PR comment.
func Comment(r Report) string {
	var b strings.Builder
	b.WriteString(Marker + "\n## depguard Report Summary\n\n")
	if r.NoChanges {
		b.WriteString("No dependency changes detected.\n\n")
	} else {
		writeFindings(&b, r)
	}
	if len(r.AIUsage) > 0 {
		b.WriteString("<details>\n<summary>AI/SaaS usage added</summary>\n\n")
		for _, u := range r.AIUsage {
			b.WriteString("- " + Escape(u) + "\n")
		}
		b.WriteString("\n</details>\n\n")
	}
	return finish(&b, r)
}

func writeFindings(b *strings.Builder, r Report) {
	b.WriteString(badge("Malware", r.any(func(p Package) bool { return p.Malware })) + " ")
	b.WriteString(badge("Vulnerability", r.any(func(p Package) bool { return p.Vulnerable })) + " ")
	b.WriteString(badge("License", r.any(func(p Package) bool { return p.RiskyLicense }) || r.hasFindings("license")) + "\n\n")

	if len(r.Packages) == 0 {
		b.WriteString("No new or changed packages to evaluate.\n")
	} else {
		fmt.Fprintf(b, "<details>\n<summary>Package Details (%d)</summary>\n\n", len(r.Packages))
		b.WriteString("| Package | Dependency | Malware | Vulnerability | Risky License | Report |\n|---|---|:---:|:---:|:---:|:---:|\n")
		for _, p := range r.Packages {
			fmt.Fprintf(b, "| `%s @ %s`<br>%s | %s | %s | %s | %s | [🔗](%s) |\n",
				codeSafe(p.Name), codeSafe(p.Version), Escape(p.ManifestPath), depLabel(p),
				mark(p.Malware), mark(p.Vulnerable), mark(p.RiskyLicense), r.scanURL())
		}
		b.WriteString("\n</details>\n\n")
	}

	if len(r.Violations) > 0 {
		fmt.Fprintf(b, "<details>\n<summary>Policy Violations (%d)</summary>\n\n", len(r.Violations))
		for _, v := range r.Violations {
			fmt.Fprintf(b, "- **%s** (%s) — `%s @ %s` in %s: %s\n", Escape(v.Rule), Escape(v.Category),
				codeSafe(v.Package.Name), codeSafe(v.Package.Version), Escape(v.Package.ManifestPath), Escape(v.Summary))
			for _, vu := range v.Vulns {
				fmt.Fprintf(b, "  - %s (%s)\n", Escape(vu.ID), Escape(vu.Risk))
			}
			if via := viaText(v.Package.Via); via != "" {
				b.WriteString("  - " + via + "\n")
			}
			fmt.Fprintf(b, "  - Fix: %s\n", fixHint(v.Category))
		}
		b.WriteString("\n</details>\n\n")
	}
	writeFindingSection(b, r, "suspicious", "Suspicious packages")
	writeFindingSection(b, r, "license", "License issues")
}

func (r Report) hasFindings(category string) bool {
	for _, f := range r.Findings {
		if f.Category == category {
			return true
		}
	}
	return false
}

// pkg finds the package a finding is about (name@version, same manifest preferred).
func (r Report) pkg(nameVersion, manifest string) (Package, bool) {
	var found Package
	ok := false
	for _, p := range r.Packages {
		if p.Name+"@"+p.Version == nameVersion {
			if p.ManifestPath == manifest {
				return p, true
			}
			if !ok {
				found, ok = p, true
			}
		}
	}
	return found, ok
}

func writeFindingSection(b *strings.Builder, r Report, category, title string) {
	var fs []Finding
	for _, f := range r.Findings {
		if f.Category == category {
			fs = append(fs, f)
		}
	}
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(b, "<details>\n<summary>%s (%d)</summary>\n\n", title, len(fs))
	for _, f := range fs {
		block := ""
		if f.Blocking {
			block = ", blocking"
		}
		fmt.Fprintf(b, "- **%s** (%s%s) — `%s` in %s: %s\n", Escape(f.Rule), Escape(f.Severity), block,
			codeSafe(f.Package), Escape(f.ManifestPath), Escape(f.Summary))
		if p, ok := r.pkg(f.Package, f.ManifestPath); ok {
			if via := viaText(p.Via); via != "" {
				b.WriteString("  - " + via + "\n")
			}
		}
	}
	b.WriteString("\n</details>\n\n")
}

// depLabel is "direct", "transitive (depth n)" or "unknown", plus ", dev".
func depLabel(p Package) string {
	l := "unknown"
	switch {
	case p.Direct == nil:
	case *p.Direct:
		l = "direct"
	case p.Depth > 1:
		l = fmt.Sprintf("transitive (depth %d)", p.Depth)
	default:
		l = "transitive"
	}
	if p.Dev {
		l += ", dev"
	}
	return l
}

// viaText is "Introduced via a@1 → b@2 → pkg@3" (escaped) for transitive chains.
func viaText(via []string) string {
	if len(via) < 2 {
		return ""
	}
	parts := make([]string, len(via))
	for i, v := range via {
		parts[i] = Escape(v)
	}
	return "Introduced via " + strings.Join(parts, " → ")
}

func finish(b *strings.Builder, r Report) string {
	fmt.Fprintf(b, "\n[View complete scan results →](%s)\n\n<sub>Generated by depguard</sub>\n", r.scanURL())
	return Truncate(b.String(), r.scanURL())
}

// codeSafe makes text safe inside an inline code span within a table cell.
func codeSafe(s string) string {
	s = strings.NewReplacer("`", "'", "|", "\\|", "\n", " ", "\r", " ").Replace(s)
	// Mentions don't render inside code spans, but keep it consistent.
	return strings.ReplaceAll(s, "@", "@‍")
}

// Truncate cuts s to MaxLen bytes on a line boundary and appends a link.
func Truncate(s, fullURL string) string {
	if len(s) <= MaxLen {
		return s
	}
	suffix := fmt.Sprintf("\n\n… truncated, see [full report](%s)\n", fullURL)
	cut := s[:MaxLen-len(suffix)]
	if i := strings.LastIndexByte(cut, '\n'); i > 0 {
		cut = cut[:i]
	}
	for !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	// An open <details> would swallow the suffix; close it.
	if strings.Count(cut, "<details>") > strings.Count(cut, "</details>") {
		cut += "\n</details>"
	}
	return cut + suffix
}

// Annotation is a check-run annotation on a manifest file.
type Annotation struct {
	Path, Level, Title, Message string
}

// CheckRun returns the check-run title, summary (≤ MaxLen) and annotations.
// Conclusion is decided by the caller (block vs warn mode).
func CheckRun(r Report) (title, summary string, anns []Annotation) {
	switch {
	case r.NoChanges:
		title = "No dependency changes detected"
	case len(r.Violations) == 0:
		title = fmt.Sprintf("No policy violations in %d new or changed packages", len(r.Packages))
	default:
		title = fmt.Sprintf("%d policy violation(s) in new or changed packages", len(r.Violations))
	}
	summary = strings.Replace(Comment(r), Marker+"\n", "", 1)
	for _, v := range r.Violations {
		level := "warning"
		if v.Category == "malware" || v.Category == "vulnerability" {
			level = "failure"
		}
		msg := v.Summary
		for _, vu := range v.Vulns {
			msg += "\n" + vu.ID + " (" + vu.Risk + ")"
		}
		anns = append(anns, Annotation{
			Path:    v.Package.ManifestPath,
			Level:   level,
			Title:   fmt.Sprintf("%s: %s@%s", v.Rule, v.Package.Name, v.Package.Version),
			Message: msg + "\n" + fixHint(v.Category),
		})
	}
	return title, summary, anns
}
