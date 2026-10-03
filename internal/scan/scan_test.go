package scan

import (
	"os"
	"testing"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

func TestParseNpmLockfile(t *testing.T) {
	const lf = "/home/manas/Documents/the_interview_pict/package-lock.json"
	if _, err := os.Stat(lf); err != nil {
		t.Skip("sample lockfile not present")
	}
	ms, err := Parse([]Lockfile{{Path: lf, RepoPath: "package-lock.json"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || len(ms[0].GetPackages()) == 0 {
		t.Fatalf("expected one manifest with packages, got %d manifests", len(ms))
	}
	if ms[0].Ecosystem != models.EcosystemNpm {
		t.Fatalf("ecosystem = %q", ms[0].Ecosystem)
	}
}

func ptr[T any](v T) *T { return &v }

func vuln(id string, risk insightapi.PackageVulnerabilitySeveritiesRisk) insightapi.PackageVulnerability {
	sev := []struct {
		Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
		Score *string                                        `json:"score,omitempty"`
		Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
	}{{Risk: ptr(risk), Type: ptr(insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3)}}
	return insightapi.PackageVulnerability{Id: ptr(id), Severities: &sev}
}

func TestDefaultPolicy(t *testing.T) {
	p, err := NewPolicy(DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(v []insightapi.PackageVulnerability, lic []insightapi.License) *models.Package {
		pkg := &models.Package{Manifest: models.NewPackageManifestFromLocal("x", models.EcosystemNpm)}
		pkg.Name, pkg.Version = "pkg", "1.0.0"
		pkg.Insights = &insightapi.PackageVersionInsight{Vulnerabilities: &v, Licenses: &lic}
		return pkg
	}
	cases := []struct {
		name string
		pkg  *models.Package
		want []string
	}{
		{"clean", mk(nil, []insightapi.License{"MIT"}), nil},
		{"malware", mk([]insightapi.PackageVulnerability{vuln("MAL-2024-1", insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL)}, nil), []string{"malicious-package"}},
		{"high vuln", mk([]insightapi.PackageVulnerability{vuln("GHSA-x", insightapi.PackageVulnerabilitySeveritiesRiskHIGH)}, nil), []string{"critical-or-high-vulnerability"}},
		{"medium vuln", mk([]insightapi.PackageVulnerability{vuln("GHSA-y", insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM)}, nil), nil},
		{"agpl", mk(nil, []insightapi.License{"AGPL-3.0-only"}), []string{"risky-license"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs, err := p.Evaluate(c.pkg)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, v := range vs {
				got = append(got, v.Rule.Name)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v want %v", got, c.want)
				}
			}
		})
	}
}
