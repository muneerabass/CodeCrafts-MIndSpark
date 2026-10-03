package pkgrules

import (
	"context"
	"slices"
	"testing"

	"github.com/safedep/vet/pkg/models"

	"github.com/depguard/depguard/internal/scan"
)

func pkg(eco, name, version string) *models.Package {
	p := &models.Package{Manifest: models.NewPackageManifestFromLocal("x", eco)}
	p.Name, p.Version = name, version
	return p
}

func TestRangeContains(t *testing.T) {
	cases := []struct {
		eco, rng, version string
		want              bool
	}{
		{"npm", ">=4.17.21", "4.17.15", false},
		{"npm", ">=4.17.21", "4.17.21", true},
		{"npm", ">=4.17.21 <5", "5.0.0", false},
		{"npm", ">= 4.17.21, < 5", "4.18.0", true},
		{"npm", "<2 || >=3.1", "2.5.0", false},
		{"npm", "<2 || >=3.1", "3.2.0", true},
		{"npm", "1.2.3", "1.2.3", true},
		{"npm", "!=1.2.3", "1.2.3", false},
		{"PyPI", ">=2.20", "2.19.0", false},
		{"PyPI", ">=2.20", "2.31.0", true},
		{"PyPI", "<3.0a1", "3.0.0", false},
		{"Go", ">=0.3.8", "v0.3.0", false},
		{"Go", ">=v0.3.8", "v0.14.0", true},
		{"crates.io", "<0.2", "0.1.45", true},
		{"crates.io", ">=0.2.23", "0.1.45", false},
		{"npm", "", "0.0.1", true},
	}
	for _, c := range cases {
		r, err := ParseRange(c.rng)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", c.rng, err)
		}
		if got, err := r.Contains(c.eco, c.version); err != nil || got != c.want {
			t.Errorf("%s %q contains %s = %v (%v), want %v", c.eco, c.rng, c.version, got, err, c.want)
		}
	}
	for _, bad := range []string{">=", "<<1", "||", ">=1 <=>2"} {
		if _, err := ParseRange(bad); err == nil {
			t.Errorf("ParseRange(%q) accepted", bad)
		}
	}
}

func TestFindings(t *testing.T) {
	rules := []scan.PackageRule{
		{Ecosystem: "npm", Name: "lodash", Versions: ">=4.17.21", Reason: "prototype pollution fixes"},
		{Name: "request", Deny: true, Reason: "deprecated, use undici"},
		{Ecosystem: "npm", Name: "@types/*", Allow: true},
		{Ecosystem: "pypi", Name: "Django", Versions: "<5", Severity: scan.SeverityMedium},
	}
	if err := Validate(rules); err != nil {
		t.Fatal(err)
	}
	c := New(rules)
	got := func(p *models.Package) []string {
		var s []string
		for _, f := range c.Findings(p) {
			s = append(s, f.Rule+":"+f.Severity+map[bool]string{true: ":block", false: ":warn"}[f.Blocking])
		}
		return s
	}
	if r := got(pkg(models.EcosystemNpm, "lodash", "4.17.15")); !slices.Equal(r, []string{"version-not-allowed:high:block"}) {
		t.Errorf("old lodash: %v", r)
	}
	if r := got(pkg(models.EcosystemNpm, "lodash", "4.17.21")); len(r) != 0 {
		t.Errorf("new lodash: %v", r)
	}
	if r := got(pkg(models.EcosystemNpm, "request", "2.88.2")); !slices.Equal(r, []string{"package-denied:high:block"}) {
		t.Errorf("request: %v", r)
	}
	if r := got(pkg(models.EcosystemPyPI, "django", "5.0.1")); !slices.Equal(r, []string{"version-not-allowed:medium:warn"}) {
		t.Errorf("django: %v", r)
	}
	if r := got(pkg(models.EcosystemPyPI, "lodash", "1.0.0")); len(r) != 0 {
		t.Errorf("ecosystem filter: %v", r)
	}
	if !Trusted(rules, pkg(models.EcosystemNpm, "@types/node", "20.0.0")) || Trusted(rules, pkg(models.EcosystemNpm, "types-node", "1.0.0")) {
		t.Error("glob allow rule")
	}
	fs, _ := c.Check(context.Background(), scan.CheckInput{Packages: []*models.Package{pkg(models.EcosystemNpm, "request", "2.0.0"), pkg(models.EcosystemNpm, "lodash", "3.0.0")}})
	if len(fs) != 2 {
		t.Errorf("Check: %d findings", len(fs))
	}
	for _, bad := range [][]scan.PackageRule{{{Name: ""}}, {{Name: "x", Ecosystem: "cobol"}}, {{Name: "x", Deny: true, Allow: true}}, {{Name: "x", Versions: ">="}}, {{Name: "x", Severity: "huge"}}} {
		if Validate(bad) == nil {
			t.Errorf("Validate accepted %+v", bad)
		}
	}
}
