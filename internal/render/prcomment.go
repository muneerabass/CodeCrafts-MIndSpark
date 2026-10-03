package render

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// RerunMarker sits on the re-run checkbox line of the PR comment. Ticking the
// box edits our comment; the issue_comment webhook sees "[x]" next to it.
const RerunMarker = "<!-- depguard:rerun -->"

// Check states for the status pills.
const (
	StatePass    = "pass"
	StateWarn    = "warn"
	StateFail    = "fail"
	StateSkip    = "skip"
	StatePending = "pending"
)

// PRChecks are the pills shown on top of the PR comment, in order.
var PRChecks = []string{"malware", "vulnerability", "license", "suspicious", "code-review"}

// PRSummary is the dependency part of a PR review. It is stored with the scan
// (scans.pr_summary) so the comment can be re-rendered when the AI review ends.
type PRSummary struct {
	ScanID     string            `json:"scan_id"`
	NoChanges  bool              `json:"no_changes"`
	Conclusion string            `json:"conclusion"` // success | neutral | failure
	Checks     map[string]string `json:"checks"`     // malware|vulnerability|license|suspicious -> state
	Fixes      []FixItem         `json:"fixes"`      // most important first
	Details    string            `json:"details"`    // collapsible package/violation sections (markdown)
	AIUsage    []string          `json:"ai_usage"`
	Packages   int               `json:"packages"`
	Labels     []string          `json:"labels"` // dependency labels: dependencies, malware, vulnerable, license, ...
}

// FixItem is one issue to fix before merging, with the command that fixes it when known.
type FixItem struct {
	Severity string `json:"severity"` // critical | high | medium | low
	Blocking bool   `json:"blocking"`
	Title    string `json:"title"`
	Command  string `json:"command,omitempty"`
	Note     string `json:"note,omitempty"`
	Kind     string `json:"kind"` // malware | vulnerability | policy | license | suspicious
	KEV      bool   `json:"kev,omitempty"`
	Direct   bool   `json:"direct,omitempty"`
}

// ReviewFinding is a code-review finding on the PR diff.
type ReviewFinding struct {
	Source      string `json:"source"` // rules | ai
	File        string `json:"file"`
	Line        int    `json:"line"`
	Severity    string `json:"severity"` // critical | high | medium | low
	Category    string `json:"category"`
	Title       string `json:"title"`
	Explanation string `json:"explanation,omitempty"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// PRReview is the code review of the PR head (rules + AI).
type PRReview struct {
	Findings []ReviewFinding `json:"findings"`
	Labels   []string        `json:"labels"`
	AIStatus string          `json:"ai_status"` // queued | running | done | skipped | rate_limited | failed
	AINote   string          `json:"ai_note"`
	AIModel  string          `json:"ai_model"`
	AISum    string          `json:"ai_summary"`
	Files    int             `json:"files_reviewed"`
	Truncate bool            `json:"truncated"`
}

// CommentSettings is the team's PR comment configuration.
type CommentSettings struct {
	Sections      map[string]bool // summary, vulnerabilities, malware, licenses, suspicious, attack_paths, code_review, fix_commands, run_config
	MentionAuthor bool
	Header        string // team markdown, trusted (admins write it)
	Footer        string
	PolicyNote    string // e.g. "block mode on · vulnerabilities ≥ HIGH"
}

func (c CommentSettings) on(section string) bool {
	if c.Sections == nil {
		return true
	}
	v, ok := c.Sections[section]
	return !ok || v
}

// PRCommentInput is everything PRComment needs.
type PRCommentInput struct {
	PublicURL    string // dashboard base URL (badges and links)
	ProjectID    string
	PRNumber     int
	Author       string
	HeadSHA      string
	Commits      []string // head SHAs reviewed, newest first
	Summary      PRSummary
	Review       PRReview
	Settings     CommentSettings
	Urgency      int
	Level        string   // critical | high | medium | low | clean | pending
	Reasons      []string // top reasons
	FixedNow     bool     // earlier review had blocking issues, this one has none
	BlockingNote string   // e.g. "block mode is on"
}

// Summarize builds the stored dependency summary of a PR scan.
func Summarize(r Report, conclusion string) PRSummary {
	s := PRSummary{ScanID: r.ScanID, NoChanges: r.NoChanges, Conclusion: conclusion, AIUsage: r.AIUsage,
		Packages: len(r.Packages), Checks: map[string]string{}}
	state := func(fail, warn bool) string {
		switch {
		case fail:
			return StateFail
		case warn:
			return StateWarn
		}
		return StatePass
	}
	malware := r.any(func(p Package) bool { return p.Malware })
	vulnBlock := false
	for _, v := range r.Violations {
		vulnBlock = vulnBlock || v.Category == "vulnerability"
	}
	vulnerable := r.any(func(p Package) bool { return p.Vulnerable })
	licBlock, licWarn, susBlock, susWarn := false, r.any(func(p Package) bool { return p.RiskyLicense }), false, false
	for _, f := range r.Findings {
		switch f.Category {
		case "license":
			licBlock, licWarn = licBlock || f.Blocking, true
		case "suspicious":
			susBlock, susWarn = susBlock || f.Blocking, true
		}
	}
	for _, v := range r.Violations {
		if v.Category == "license" {
			licBlock = true
		}
	}
	s.Checks["malware"] = state(malware, false)
	s.Checks["vulnerability"] = state(vulnBlock, vulnerable)
	s.Checks["license"] = state(licBlock, licWarn)
	s.Checks["suspicious"] = state(susBlock, susWarn)

	if !r.NoChanges {
		s.Labels = append(s.Labels, "dependencies")
	}
	for k, l := range map[string]string{"malware": "malware", "vulnerability": "vulnerable", "license": "license-risk", "suspicious": "suspicious-package"} {
		if s.Checks[k] != StatePass {
			s.Labels = append(s.Labels, l)
		}
	}
	slices.Sort(s.Labels)

	// Fix list: malware, then vulnerable packages (worst first), then blocking findings.
	for _, p := range r.Packages {
		if p.Malware {
			s.Fixes = append(s.Fixes, FixItem{Severity: "critical", Blocking: true, Kind: "malware", Direct: p.Direct != nil && *p.Direct,
				Title:   fmt.Sprintf("Remove malicious package `%s@%s`", codeSafe(p.Name), codeSafe(p.Version)),
				Command: RemoveCommand(p.Ecosystem, p.Name, p.ManifestPath),
				Note:    "Rotate any credentials the build environment had access to."})
		}
	}
	type vulnPkg struct {
		p    Package
		risk string
		fix  string
		ids  []string
		kev  bool
	}
	var vps []vulnPkg
	for _, p := range r.Packages {
		if !p.Vulnerable || p.Malware {
			continue
		}
		vp := vulnPkg{p: p, risk: "LOW"}
		for _, v := range p.Vulns {
			if strings.HasPrefix(v.ID, "MAL-") {
				continue
			}
			vp.kev = vp.kev || v.KEV
			vp.ids = append(vp.ids, v.ID)
			if rankOf(v.Risk) < rankOf(vp.risk) {
				vp.risk = v.Risk
			}
			if v.FixedIn != "" && (vp.fix == "" || compareVersions(v.FixedIn, vp.fix) > 0) {
				vp.fix = v.FixedIn
			}
		}
		vps = append(vps, vp)
	}
	slices.SortStableFunc(vps, func(a, b vulnPkg) int { return rankOf(a.risk) - rankOf(b.risk) })
	blockingVuln := map[string]bool{}
	for _, v := range r.Violations {
		if v.Category == "vulnerability" {
			blockingVuln[v.Package.Name+"@"+v.Package.Version] = true
		}
	}
	for _, vp := range vps {
		ids := vp.ids
		if len(ids) > 3 {
			ids = append(ids[:3:3], fmt.Sprintf("+%d more", len(vp.ids)-3))
		}
		it := FixItem{Severity: strings.ToLower(vp.risk), Blocking: blockingVuln[vp.p.Name+"@"+vp.p.Version], Kind: "vulnerability",
			KEV: vp.kev, Direct: vp.p.Direct != nil && *vp.p.Direct,
			Title: fmt.Sprintf("`%s@%s` has %s (%s)", codeSafe(vp.p.Name), codeSafe(vp.p.Version), plural(len(vp.ids), "known vulnerability", "known vulnerabilities"), Escape(strings.Join(ids, ", ")))}
		if vp.fix != "" {
			it.Command = UpgradeCommand(vp.p.Ecosystem, vp.p.Name, vp.fix, vp.p.ManifestPath)
		}
		if len(vp.p.Via) > 1 {
			it.Note = fmt.Sprintf("Comes in through `%s`; update it or pin `%s` with an override.", codeSafe(vp.p.Via[0]), codeSafe(vp.p.Name))
		}
		s.Fixes = append(s.Fixes, it)
	}
	for _, f := range r.Findings {
		if !f.Blocking {
			continue
		}
		s.Fixes = append(s.Fixes, FixItem{Severity: strings.ToLower(f.Severity), Blocking: true, Kind: f.Category,
			Title: fmt.Sprintf("`%s`: %s", codeSafe(f.Package), Escape(f.Summary))})
	}
	for _, v := range r.Violations {
		if v.Category == "vulnerability" || v.Category == "malware" {
			continue // covered above
		}
		s.Fixes = append(s.Fixes, FixItem{Severity: "high", Blocking: true, Kind: "policy",
			Title: fmt.Sprintf("`%s@%s` breaks rule **%s**: %s", codeSafe(v.Package.Name), codeSafe(v.Package.Version), Escape(v.Rule), Escape(v.Summary))})
	}
	slices.SortStableFunc(s.Fixes, func(a, b FixItem) int {
		if a.Blocking != b.Blocking {
			if a.Blocking {
				return -1
			}
			return 1
		}
		return sevRank(a.Severity) - sevRank(b.Severity)
	})

	var d strings.Builder
	writeDetails(&d, r)
	s.Details = d.String()
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

// UpgradeCommand is the command that moves a package to a fixed version.
func UpgradeCommand(eco, name, version, manifest string) string {
	base := path.Base(manifest)
	switch strings.ToLower(eco) {
	case "npm":
		switch base {
		case "yarn.lock":
			return fmt.Sprintf("yarn add %s@%s", name, version)
		case "pnpm-lock.yaml":
			return fmt.Sprintf("pnpm add %s@%s", name, version)
		case "bun.lock", "bun.lockb":
			return fmt.Sprintf("bun add %s@%s", name, version)
		}
		return fmt.Sprintf("npm install %s@%s", name, version)
	case "pypi":
		switch base {
		case "uv.lock":
			return fmt.Sprintf(`uv add "%s>=%s"`, name, version)
		case "poetry.lock":
			return fmt.Sprintf(`poetry add "%s>=%s"`, name, version)
		}
		return fmt.Sprintf(`pip install "%s>=%s"`, name, version)
	case "go":
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		return fmt.Sprintf("go get %s@%s && go mod tidy", name, version)
	case "cargo", "crates.io":
		return fmt.Sprintf("cargo update -p %s --precise %s", name, version)
	case "rubygems":
		return fmt.Sprintf("bundle update %s", name)
	case "packagist":
		return fmt.Sprintf("composer require %s:^%s", name, version)
	case "nuget":
		return fmt.Sprintf("dotnet add package %s --version %s", name, version)
	case "maven":
		return fmt.Sprintf("set %s to %s in %s", name, version, base)
	}
	return ""
}

// RemoveCommand is the command that removes a package.
func RemoveCommand(eco, name, manifest string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "npm uninstall " + name
	case "pypi":
		if path.Base(manifest) == "uv.lock" {
			return "uv remove " + name
		}
		if path.Base(manifest) == "poetry.lock" {
			return "poetry remove " + name
		}
		return "pip uninstall " + name
	case "go":
		return "go get " + name + "@none && go mod tidy"
	case "cargo", "crates.io":
		return "cargo remove " + name
	}
	return ""
}

// writeDetails is the collapsible package and finding sections.
func writeDetails(b *strings.Builder, r Report) {
	if len(r.Packages) > 0 {
		fmt.Fprintf(b, "<details>\n<summary>📦 Package details (%d)</summary>\n\n", len(r.Packages))
		b.WriteString("| Package | Dependency | Malware | Vulnerability | Risky license |\n|---|---|:---:|:---:|:---:|\n")
		for _, p := range r.Packages {
			fmt.Fprintf(b, "| `%s @ %s`<br>%s | %s | %s | %s | %s |\n", codeSafe(p.Name), codeSafe(p.Version), Escape(p.ManifestPath),
				depLabel(p), mark(p.Malware), mark(p.Vulnerable), mark(p.RiskyLicense))
		}
		b.WriteString("\n</details>\n\n")
	}
	if len(r.Violations) > 0 {
		fmt.Fprintf(b, "<details>\n<summary>🚫 Policy violations (%d)</summary>\n\n", len(r.Violations))
		for _, v := range r.Violations {
			fmt.Fprintf(b, "- **%s** (%s) — `%s @ %s` in %s: %s\n", Escape(v.Rule), Escape(v.Category),
				codeSafe(v.Package.Name), codeSafe(v.Package.Version), Escape(v.Package.ManifestPath), Escape(v.Summary))
			for _, vu := range v.Vulns {
				fmt.Fprintf(b, "  - %s (%s)\n", Escape(vu.ID), Escape(vu.Risk))
			}
			if via := viaText(v.Package.Via); via != "" {
				b.WriteString("  - " + via + "\n")
			}
		}
		b.WriteString("\n</details>\n\n")
	}
	writeFindingSection(b, r, "suspicious", "🕵️ Suspicious packages")
	writeFindingSection(b, r, "license", "⚖️ License issues")
}

var levelWords = map[string]string{
	"critical": "Critical — fix before merging", "high": "High — fix before merging", "medium": "Medium — review before merging",
	"low": "Low — minor findings", "clean": "Clean", "pending": "Review in progress",
}

// PRComment renders the sticky PR comment.
func PRComment(in PRCommentInput) string {
	base := strings.TrimRight(in.PublicURL, "/")
	prURL := fmt.Sprintf("%s/pull-requests/%s/%d", base, in.ProjectID, in.PRNumber)
	scanURL := base + "/scans/" + in.Summary.ScanID
	s, rv, set := in.Summary, in.Review, in.Settings
	var b strings.Builder
	b.WriteString(Marker + "\n")
	if h := strings.TrimSpace(set.Header); h != "" {
		b.WriteString(h + "\n\n")
	}
	b.WriteString("## depguard Report Summary\n\n")

	// Status pills.
	codeState := reviewState(rv)
	for _, c := range PRChecks {
		st := s.Checks[c]
		if c == "code-review" {
			st = codeState
		}
		if st == "" {
			st = StatePass
		}
		label := strings.ToUpper(strings.ReplaceAll(c, "-", " "))
		fmt.Fprintf(&b, `<img src="%s/badges/%s-%s.svg" alt="%s: %s" height="30"> `, base, c, st, label, st)
	}
	b.WriteString("\n\n")

	// One-line verdict.
	blocking := 0
	for _, f := range s.Fixes {
		if f.Blocking {
			blocking++
		}
	}
	for _, f := range rv.Findings {
		if f.Severity == "critical" || f.Severity == "high" {
			blocking++
		}
	}
	switch {
	case s.NoChanges && len(rv.Findings) == 0 && in.Level != "pending":
		b.WriteString("No dependency changes detected. Nothing to scan.\n\n")
	case in.FixedNow && in.Level == "clean":
		b.WriteString("✅ **All issues fixed.** No blocking findings in the latest commit.\n\n")
	default:
		fmt.Fprintf(&b, "**Urgency: %s** (score %d/100)", levelWords[in.Level], in.Urgency)
		if s.Packages > 0 {
			fmt.Fprintf(&b, " · %s checked", plural(s.Packages, "new or changed package", "new or changed packages"))
		}
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b, `<a href="%s"><img src="%s/badges/review-button.svg" alt="Review in depguard" height="34"></a>`+"\n\n", prURL, base)

	// Callouts.
	if blocking > 0 && in.Level != "clean" {
		b.WriteString("> [!CAUTION]\n")
		fmt.Fprintf(&b, "> **%s must be fixed before merging.**", plural(blocking, "blocking issue", "blocking issues"))
		if in.BlockingNote != "" {
			b.WriteString(" " + Escape(in.BlockingNote) + ".")
		}
		if set.MentionAuthor && in.Author != "" {
			fmt.Fprintf(&b, " @%s", strings.TrimPrefix(in.Author, "@"))
		}
		b.WriteString("\n")
		for _, r := range in.Reasons {
			b.WriteString("> - " + r + "\n")
		}
		b.WriteString("\n")
	} else if in.Level == "medium" || in.Level == "low" {
		b.WriteString("> [!WARNING]\n> Findings to review; nothing here blocks the merge.\n")
		for _, r := range in.Reasons {
			b.WriteString("> - " + r + "\n")
		}
		b.WriteString("\n")
	}
	switch rv.AIStatus {
	case "queued", "running":
		b.WriteString("> [!NOTE]\n> The AI code review is running; this comment updates when it finishes.\n\n")
	case "rate_limited", "failed":
		fmt.Fprintf(&b, "> [!IMPORTANT]\n> AI code review delayed: %s. The rule-based review below is complete; the AI review is retried automatically.\n\n", Escape(rv.AINote))
	}

	// Fix before merging.
	if set.on("fix_commands") && len(s.Fixes) > 0 {
		b.WriteString("### Fix before merging\n\n")
		for i, f := range s.Fixes {
			if i == 8 {
				fmt.Fprintf(&b, "- … and %d more in the [full review](%s)\n", len(s.Fixes)-8, prURL)
				break
			}
			tag := strings.ToUpper(f.Severity)
			if f.Blocking {
				tag += ", blocking"
			}
			fmt.Fprintf(&b, "- **[%s]** %s\n", tag, f.Title)
			if f.Command != "" {
				fmt.Fprintf(&b, "  ```sh\n  %s\n  ```\n", f.Command)
			}
			if f.Note != "" {
				b.WriteString("  " + f.Note + "\n")
			}
		}
		b.WriteString("\n")
	}

	// Code review.
	if set.on("code_review") && len(rv.Findings) > 0 {
		fmt.Fprintf(&b, "<details open>\n<summary>🔍 Code review (%d)</summary>\n\n", len(rv.Findings))
		if rv.AISum != "" {
			b.WriteString(Escape(rv.AISum) + "\n\n")
		}
		fs := slices.Clone(rv.Findings)
		slices.SortStableFunc(fs, func(a, b ReviewFinding) int { return sevRank(a.Severity) - sevRank(b.Severity) })
		for i, f := range fs {
			if i == 15 {
				fmt.Fprintf(&b, "- … and %d more in the [full review](%s)\n", len(fs)-15, prURL)
				break
			}
			loc := Escape(f.File)
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", loc, f.Line)
			}
			src := ""
			if f.Source == "ai" {
				src = " · AI"
			}
			fmt.Fprintf(&b, "- **[%s]** `%s` — %s%s\n", strings.ToUpper(f.Severity), codeSafe(loc), Escape(f.Title), src)
			if f.Explanation != "" {
				b.WriteString("  " + Escape(f.Explanation) + "\n")
			}
			if f.Suggestion != "" {
				b.WriteString("  _Suggestion:_ " + Escape(f.Suggestion) + "\n")
			}
		}
		b.WriteString("\n</details>\n\n")
	}

	if s.Details != "" && (set.on("vulnerabilities") || set.on("licenses") || set.on("suspicious")) {
		b.WriteString(s.Details)
	}
	if len(s.AIUsage) > 0 {
		b.WriteString("<details>\n<summary>🤖 AI/SaaS usage added</summary>\n\n")
		for _, u := range s.AIUsage {
			b.WriteString("- " + Escape(u) + "\n")
		}
		b.WriteString("\n</details>\n\n")
	}
	if set.on("run_config") {
		b.WriteString("<details>\n<summary>⚙️ Run configuration</summary>\n\n")
		if set.PolicyNote != "" {
			b.WriteString("- Policy: " + Escape(set.PolicyNote) + "\n")
		}
		fmt.Fprintf(&b, "- Checks: malware, vulnerabilities, licenses, suspicious packages, package rules, code review (%s)\n", reviewEngines(rv))
		if rv.Files > 0 {
			fmt.Fprintf(&b, "- Files reviewed: %d", rv.Files)
			if rv.Truncate {
				b.WriteString(" (large diff: the review covered the first part)")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n</details>\n\n")
	}
	if len(in.Commits) > 0 {
		b.WriteString("<details>\n<summary>📥 Commits reviewed</summary>\n\n")
		for _, c := range in.Commits {
			if len(c) > 12 {
				c = c[:12]
			}
			b.WriteString("- `" + codeSafe(c) + "`\n")
		}
		b.WriteString("\n</details>\n\n")
	}
	b.WriteString("- [ ] " + RerunMarker + " Re-run depguard review\n\n")
	fmt.Fprintf(&b, "[View complete scan results →](%s)\n\n", scanURL)
	if f := strings.TrimSpace(set.Footer); f != "" {
		b.WriteString(f + "\n\n")
	}
	b.WriteString("<sub>This report is generated by the depguard GitHub App</sub>\n")
	return Truncate(b.String(), prURL)
}

func reviewState(rv PRReview) string {
	worst := ""
	for _, f := range rv.Findings {
		if worst == "" || sevRank(f.Severity) < sevRank(worst) {
			worst = f.Severity
		}
	}
	switch {
	case worst == "critical" || worst == "high":
		return StateFail
	case worst != "":
		return StateWarn
	case rv.AIStatus == "queued" || rv.AIStatus == "running":
		return StatePending
	}
	return StatePass
}

func reviewEngines(rv PRReview) string {
	switch rv.AIStatus {
	case "done":
		return "rules + AI (" + rv.AIModel + ")"
	case "queued", "running":
		return "rules; AI running"
	case "rate_limited", "failed":
		return "rules; AI delayed"
	}
	return "rules"
}

// RerunRequested reports whether a comment body has the re-run box ticked.
func RerunRequested(body string) bool {
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, RerunMarker) {
			t := strings.TrimSpace(l)
			return strings.HasPrefix(t, "- [x]") || strings.HasPrefix(t, "- [X]")
		}
	}
	return false
}
