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
			{Rule: "malicious-package", Category: "malware", Summary: "Known malicious package", Package: evil, Vulns: []Vuln{{"MAL-2024-1", "CRITICAL"}}},
			{Rule: "critical-or-high-vulnerability", Category: "vulnerability", Summary: "Critical or high severity vulnerability", Package: vuln, Vulns: []Vuln{{"GHSA-xxxx", "HIGH"}}},
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
