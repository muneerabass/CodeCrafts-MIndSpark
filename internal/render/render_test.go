package render

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch (run with -update)\n--- got ---\n%s", name, got)
	}
}

func sample() Report {
	evil := Package{Name: "evil-pkg", Version: "1.0.0", Ecosystem: "npm", ManifestPath: "package-lock.json", Malware: true}
	vuln := Package{Name: "@acme/lodash", Version: "4.17.0", Ecosystem: "npm", ManifestPath: "web/package-lock.json", Vulnerable: true}
	return Report{
		PublicURL: "https://app.depguard.dev/",
		ScanID:    "01SCAN",
		Packages:  []Package{evil, vuln, {Name: "left_pad*", Version: "1.3.0", Ecosystem: "npm", ManifestPath: "package-lock.json"}},
		Violations: []Violation{
			{Rule: "malicious-package", Category: "malware", Summary: "Known malicious package", Package: evil, Vulns: []Vuln{{ID: "MAL-2024-1", Risk: "CRITICAL"}}},
			{Rule: "critical-or-high-vulnerability", Category: "vulnerability", Summary: "Critical or high severity vulnerability", Package: vuln, Vulns: []Vuln{{ID: "GHSA-xxxx", Risk: "HIGH"}}},
		},
		AIUsage: []string{"Anthropic API - AI client in app.py:8"},
	}
}

func TestCommentGolden(t *testing.T) {
	golden(t, "comment_violations.md", Comment(sample()))
	golden(t, "comment_clean.md", Comment(Report{PublicURL: "https://app.depguard.dev", ScanID: "01CLEAN",
		Packages: []Package{{Name: "react", Version: "18.2.0", ManifestPath: "package-lock.json"}}}))
	golden(t, "comment_nochanges.md", Comment(Report{PublicURL: "https://app.depguard.dev", ScanID: "01NONE", NoChanges: true}))
}

func TestCheckRunGolden(t *testing.T) {
	title, summary, anns := CheckRun(sample())
	var b strings.Builder
	b.WriteString(title + "\n---\n" + summary + "\n---\n")
	for _, a := range anns {
		b.WriteString(a.Path + " [" + a.Level + "] " + a.Title + "\n" + a.Message + "\n")
	}
	golden(t, "checkrun_violations.txt", b.String())
}

func TestEscapeNeutralizesMentionsAndMarkdown(t *testing.T) {
	got := Escape("@octocat [x](http://e) <img> `a` | b")
	if strings.Contains(got, "@octocat") || strings.Contains(got, "<img>") || strings.Contains(got, "](") {
		t.Fatalf("not escaped: %q", got)
	}
	c := Comment(Report{ScanID: "1", Packages: []Package{{Name: "@team/pkg", Version: "1`|", ManifestPath: "@org/x"}}})
	if strings.Contains(c, "@team") || strings.Contains(c, "@org") {
		t.Fatalf("mention leaked:\n%s", c)
	}
}

func TestTruncate(t *testing.T) {
	r := Report{PublicURL: "https://x", ScanID: "S"}
	for i := 0; i < 3000; i++ {
		r.Packages = append(r.Packages, Package{Name: strings.Repeat("ü", 20), Version: "1.0.0", ManifestPath: "package-lock.json", Vulnerable: true})
	}
	c := Comment(r)
	if len(c) > MaxLen {
		t.Fatalf("len %d > %d", len(c), MaxLen)
	}
	if !strings.Contains(c, "truncated, see [full report](https://x/scans/S)") || !strings.HasPrefix(c, Marker) {
		t.Fatal("missing truncation link or marker")
	}
	_, s, _ := CheckRun(r)
	if len(s) > MaxLen {
		t.Fatal("summary too long")
	}
}

func ptr[T any](v T) *T { return &v }

// riskSample: MIT project, app → express → body-parser → qs (vulnerable), a
// typosquat, a deprecated package and a GPL dependency.
func riskSample() Report {
	qs := Package{ID: "c-qs", Name: "qs", Version: "6.7.0", Ecosystem: "npm", ManifestPath: "package-lock.json", Vulnerable: true,
		Direct: ptr(false), Depth: 3, Via: []string{"express@4.17.1", "body-parser@1.19.0", "qs@6.7.0"},
		Paths:    [][]string{{"express@4.17.1", "body-parser@1.19.0", "qs@6.7.0"}, {"express@4.17.1", "qs@6.7.0"}},
		Imported: ptr(true), GraphSource: "lockfile", Licenses: []string{"BSD-3-Clause"},
		Vulns: []Vuln{{ID: "GHSA-hrpp-h998-j3pp", Risk: "HIGH", Summary: "qs prototype pollution", EPSS: 0.42, KEV: true, FixedIn: "6.7.3"}}}
	express := Package{ID: "c-express", Name: "express", Version: "4.17.1", Ecosystem: "npm", ManifestPath: "package-lock.json",
		Direct: ptr(true), Depth: 1, Via: []string{"express@4.17.1"}, Imported: ptr(true), GraphSource: "lockfile", Licenses: []string{"MIT"}}
	lodahs := Package{ID: "c-lodahs", Name: "lodahs", Version: "1.0.0", Ecosystem: "npm", ManifestPath: "package-lock.json",
		Direct: ptr(true), Depth: 1, Via: []string{"lodahs@1.0.0"}, GraphSource: "lockfile"}
	request := Package{Name: "request", Version: "2.88.2", Ecosystem: "npm", ManifestPath: "package-lock.json",
		Direct: ptr(true), Depth: 1, Dev: true, Via: []string{"request@2.88.2"}, Imported: ptr(false), GraphSource: "lockfile",
		Vulns: []Vuln{{ID: "GHSA-p8p7-x288-28g6", Risk: "MEDIUM", EPSS: 0.01}}, Vulnerable: true}
	gpl := Package{Name: "gpl-lib", Version: "2.0.0", Ecosystem: "npm", ManifestPath: "package-lock.json",
		Direct: ptr(false), Depth: 2, Via: []string{"express@4.17.1", "gpl-lib@2.0.0"}, GraphSource: "lockfile", Licenses: []string{"GPL-3.0-only"}}
	return Report{
		PublicURL: "https://app.depguard.dev", ScanID: "01RISK", Version: "main", Date: "2026-10-01",
		Project:  Project{Name: "acme/web", License: "MIT", LicenseSource: "manifest", UsageModel: "distributed_binary"},
		Packages: []Package{qs, express, lodahs, request, gpl},
		Violations: []Violation{{Rule: "vulnerability-high-or-higher", Category: "vulnerability", Summary: "Vulnerability with HIGH or higher risk",
			Package: qs, Vulns: []Vuln{{ID: "GHSA-hrpp-h998-j3pp", Risk: "HIGH"}}}},
		Findings: []Finding{
			{Rule: "typosquat", Category: "suspicious", Severity: "high", Blocking: true, Summary: "Name is one edit away from a popular package",
				Package: "lodahs@1.0.0", ManifestPath: "package-lock.json", Details: map[string]any{"similar_to": "lodash"}},
			{Rule: "deprecated", Category: "suspicious", Severity: "medium", Summary: "Package is deprecated",
				Package: "request@2.88.2", ManifestPath: "package-lock.json", Details: map[string]any{"reason": "request has been deprecated"}},
			{Rule: "license-incompatible", Category: "license", Severity: "high", Blocking: true,
				Summary: "GPL-3.0-only is incompatible with MIT when distributed as a binary",
				Package: "gpl-lib@2.0.0", ManifestPath: "package-lock.json", Details: map[string]any{"license": "GPL-3.0-only"}},
		},
	}
}

func TestRiskGolden(t *testing.T) {
	r := riskSample()
	golden(t, "comment_risk.md", Comment(r))
	for _, f := range []string{"md", "html"} {
		out, err := Full(r, f)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "full."+f, out)
	}
	j, err := Full(r, "json")
	if err != nil || !strings.Contains(j, `"attack_paths": 4`) || !strings.Contains(j, `"verdict": "fail"`) {
		t.Fatalf("json: %v %s", err, j)
	}
	if _, err := Full(r, "pdf"); err == nil {
		t.Fatal("unknown format accepted")
	}
	h, _ := Full(Report{Project: Project{Name: "<script>x</script>"}}, "html")
	if strings.Contains(h, "<script>") || strings.Contains(h, "http://") && !strings.Contains(h, "/scans/") {
		t.Fatal("html not escaped")
	}
}

func TestPathsAndScore(t *testing.T) {
	ps := Paths(riskSample())
	if len(ps) != 4 {
		t.Fatalf("paths: %+v", ps)
	}
	top := ps[0]
	// HIGH 30 + KEV 20 + EPSS 0.42·20 = 58.4, imported ×1, depth 2 ×0.95 → 55.48
	if top.Target.Name != "qs" || top.Depth != 2 || top.Score != 55 || top.DirectHead != "express@4.17.1" ||
		top.Fix != "Upgrade qs to ≥6.7.3 (via express: update express or pin qs with an override/resolution)" ||
		*top.Chain[0].ComponentID != "c-express" {
		t.Fatalf("top path: %+v", top)
	}
	for _, c := range []struct {
		risk     string
		kev      bool
		epss     float64
		imported *bool
		dev      bool
		depth    int
		mal      bool
		want     int
	}{
		{"CRITICAL", true, 1, ptr(true), false, 1, false, 80},
		{"CRITICAL", false, 0, nil, false, 1, false, 24},
		{"LOW", false, 0, ptr(false), true, 30, false, 0},
		{"MEDIUM", false, 0.5, ptr(true), false, 11, false, 13},
		{"LOW", false, 0, nil, false, 1, true, 100},
	} {
		if got := Score(c.risk, c.kev, c.epss, c.imported, c.dev, c.depth, c.mal); got != c.want {
			t.Errorf("Score(%+v) = %d want %d", c, got, c.want)
		}
	}
	if n, v := ParseNameVersion("@acme/x@1.2.3"); n != "@acme/x" || v != "1.2.3" {
		t.Fatal(n, v)
	}
}
