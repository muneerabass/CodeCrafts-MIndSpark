package scan

import (
	"slices"
	"testing"
	"time"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

func mkPkg(eco, name, version string, vs []insightapi.PackageVulnerability, lic []insightapi.License, stars int, score float32) *models.Package {
	pkg := &models.Package{Manifest: models.NewPackageManifestFromLocal("x", eco)}
	pkg.Name, pkg.Version = name, version
	projects := []insightapi.PackageProjectInfo{}
	if stars >= 0 {
		projects = append(projects, insightapi.PackageProjectInfo{Name: ptr("r"), Stars: ptr(stars)})
	}
	sc := insightapi.ScorecardContentV2{Score: ptr(score)}
	pkg.Insights = &insightapi.PackageVersionInsight{Vulnerabilities: &vs, Licenses: &lic, Projects: &projects,
		Scorecard: &insightapi.Scorecard{Content: &sc}}
	return pkg
}

func ruleNames(t *testing.T, rules []Rule, pkg *models.Package) []string {
	t.Helper()
	p, err := NewPolicy(rules)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := p.Evaluate(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, v := range vs {
		out = append(out, v.Rule.Name)
	}
	return out
}

func TestRulesFromPolicyEmptyIsDefault(t *testing.T) {
	for _, raw := range []string{"", "{}", `{"custom":[]}`} {
		rules, err := RulesFromPolicy([]byte(raw))
		if err != nil || len(rules) != len(DefaultRules()) {
			t.Fatalf("%q: %v %d", raw, err, len(rules))
		}
	}
}

func TestPresetsToCEL(t *testing.T) {
	raw := `{"presets":{"vulnerability":{"min_risk":"MEDIUM"},"malware":{"enabled":true},
	  "license":{"deny":["GPL-3.0","SSPL\"x"]},"popularity":{"enabled":true,"min_stars":100},
	  "maintenance":{"enabled":true,"min_scorecard":4.5}},
	  "custom":[{"name":"no-left-pad","category":"other","summary":"banned","expr":"pkg.name == \"left-pad\""}]}`
	rules, err := RulesFromPolicy([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		pkg  *models.Package
		want []string
	}{
		{"clean", mkPkg(models.EcosystemNpm, "a", "1", nil, []insightapi.License{"MIT"}, 500, 7), nil},
		{"medium", mkPkg(models.EcosystemNpm, "a", "1", []insightapi.PackageVulnerability{vuln("GHSA-1", insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM)}, nil, 500, 7), []string{"vulnerability-medium-or-higher"}},
		{"low ignored", mkPkg(models.EcosystemNpm, "a", "1", []insightapi.PackageVulnerability{vuln("GHSA-1", insightapi.PackageVulnerabilitySeveritiesRiskLOW)}, nil, 500, 7), nil},
		{"malware only", mkPkg(models.EcosystemNpm, "a", "1", []insightapi.PackageVulnerability{vuln("MAL-1", insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL)}, nil, 500, 7), []string{"malicious-package"}},
		{"gpl", mkPkg(models.EcosystemNpm, "a", "1", nil, []insightapi.License{"GPL-3.0-only"}, 500, 7), []string{"denied-license"}},
		{"unpopular", mkPkg(models.EcosystemNpm, "a", "1", nil, nil, 3, 7), []string{"low-popularity"}},
		{"no project data", mkPkg(models.EcosystemNpm, "a", "1", nil, nil, -1, 7), nil},
		{"low scorecard", mkPkg(models.EcosystemNpm, "a", "1", nil, nil, 500, 2), []string{"low-scorecard"}},
		{"no scorecard", mkPkg(models.EcosystemNpm, "a", "1", nil, nil, 500, 0), nil},
		{"custom", mkPkg(models.EcosystemNpm, "left-pad", "1", nil, nil, 500, 7), []string{"no-left-pad"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ruleNames(t, rules, c.pkg); !slices.Equal(got, c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestPresetsOff(t *testing.T) {
	rules, err := RulesFromPolicy([]byte(`{"presets":{"vulnerability":{"min_risk":"OFF"},"malware":{"enabled":false}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("want no rules, got %v", rules)
	}
}

func TestExclusionsCannotSuppressMalware(t *testing.T) {
	p, _ := NewPolicy(DefaultRules())
	mal := mkPkg(models.EcosystemNpm, "evil", "1.0.0", []insightapi.PackageVulnerability{
		vuln("MAL-2024-1", insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL),
		vuln("GHSA-z", insightapi.PackageVulnerabilitySeveritiesRiskHIGH)}, nil, 1, 1)
	vul := mkPkg(models.EcosystemNpm, "lodash", "4.17.0", []insightapi.PackageVulnerability{
		vuln("GHSA-y", insightapi.PackageVulnerabilitySeveritiesRiskHIGH)}, nil, 1, 1)
	var vs []Violation
	for _, pkg := range []*models.Package{mal, vul} {
		v, _ := p.Evaluate(pkg)
		vs = append(vs, v...)
	}
	if len(vs) != 3 {
		t.Fatalf("setup: %d violations", len(vs))
	}
	now := time.Now()
	past := now.Add(-time.Hour)
	ex := []Exclusion{{Ecosystem: "npm", Name: "evil", Version: "*"}, {Ecosystem: "NPM", Name: "lodash", Version: "4.17.0"}}
	got := ApplyExclusions(vs, ex, now)
	if len(got) != 1 || got[0].Rule.Name != "malicious-package" {
		t.Fatalf("got %+v", got)
	}
	// Expired / other-version exclusions do nothing.
	ex = []Exclusion{{Ecosystem: "npm", Name: "lodash", Version: "*", ExpiresAt: &past}, {Ecosystem: "npm", Name: "lodash", Version: "1.0.0"}}
	if got := ApplyExclusions(vs, ex, now); len(got) != 3 {
		t.Fatalf("got %d", len(got))
	}
}

func manifest(path string, pkgs ...[2]string) *models.PackageManifest {
	m := models.NewPackageManifestFromLocal(path, models.EcosystemNpm)
	m.SetDisplayPath(path)
	for _, p := range pkgs {
		pkg := &models.Package{Manifest: m}
		pkg.Name, pkg.Version = p[0], p[1]
		m.AddPackage(pkg)
	}
	return m
}

func TestDiff(t *testing.T) {
	base := []*models.PackageManifest{manifest("package-lock.json", [2]string{"a", "1"}, [2]string{"b", "1"})}
	head := []*models.PackageManifest{
		manifest("package-lock.json", [2]string{"a", "1"}, [2]string{"b", "2"}, [2]string{"c", "1"}, [2]string{"c", "1"}),
		manifest("web/package-lock.json", [2]string{"a", "1"}),
	}
	var got []string
	for _, c := range Diff(base, head) {
		got = append(got, c.Path+":"+c.Package.GetName()+"@"+c.Package.GetVersion()+":"+c.Kind)
	}
	want := []string{"package-lock.json:b@2:changed", "package-lock.json:c@1:added", "web/package-lock.json:a@1:added"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if len(Diff(head, head)) != 0 {
		t.Fatal("identical manifests must have no changes")
	}
}

func TestIsManifest(t *testing.T) {
	yes := []string{"package-lock.json", "a/yarn.lock", "pnpm-lock.yaml", "bun.lock", "requirements.txt", "poetry.lock",
		"Pipfile.lock", "uv.lock", "go.mod", "pom.xml", "gradle.lockfile", "Cargo.lock", "Gemfile.lock", "composer.lock",
		".github/workflows/ci.yml"}
	no := []string{"package.json", "README.md", "main.go", "mix.lock", "pubspec.lock", "pdm.lock", "npm-shrinkwrap.json"}
	for _, p := range yes {
		if !IsManifest(p) {
			t.Errorf("%s should be a manifest", p)
		}
	}
	for _, p := range no {
		if IsManifest(p) {
			t.Errorf("%s should not be a manifest", p)
		}
	}
}

func TestSuspiciousAndLicensePresetDefaults(t *testing.T) {
	// Policies saved before these presets existed keep license checks on and
	// get the default suspicious rules.
	pc, err := ParsePolicy([]byte(`{"presets":{"vulnerability":{"min_risk":"HIGH"},"license":{"deny":["GPL-3.0"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	l := pc.Presets.License
	if !l.Enabled || l.BlockingSeverity != SeverityHigh || !slices.Equal(l.Deny, []string{"GPL-3.0"}) {
		t.Fatalf("license = %+v", l)
	}
	if s := pc.Presets.Suspicious; s == nil || !s.Typosquat || s.NoSourceRepo || s.UnmaintainedMonths != 24 ||
		!slices.Equal(s.Blocking, []string{"typosquat", "unusual-behaviour"}) {
		t.Fatalf("suspicious = %+v", s)
	}

	pc, err = ParsePolicy([]byte(`{"presets":{"license":{"enabled":false,"blocking_severity":"medium"},
	  "suspicious":{"unmaintained":false,"no_source_repo":true,"blocking":[]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if l := pc.Presets.License; l.Enabled || l.BlockingSeverity != "medium" {
		t.Fatalf("license = %+v", l)
	}
	if s := pc.Presets.Suspicious; s.Unmaintained || !s.NoSourceRepo || !s.Typosquat || !s.Deprecated || len(s.Blocking) != 0 {
		t.Fatalf("suspicious = %+v", s)
	}

	// The new presets add no CEL rules; denied-license still comes from deny.
	rules, err := RulesFromPolicy([]byte(`{"presets":{"suspicious":{"typosquat":true},"license":{"enabled":true}}}`))
	if err != nil || len(rules) != 0 {
		t.Fatalf("rules = %v, %v", rules, err)
	}
	if _, err := ParsePolicy([]byte(`{"presets":`)); err == nil {
		t.Fatal("bad JSON accepted")
	}
}
