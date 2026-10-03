package scan

import (
	"testing"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

func TestVulnsReadsFixedIn(t *testing.T) {
	v := vuln("GHSA-q", insightapi.PackageVulnerabilitySeveritiesRiskHIGH)
	rel := []string{"CVE-2022-1", fixedInPrefix + "6.7.3"}
	v.Related = &rel
	pkg := &models.Package{Insights: &insightapi.PackageVersionInsight{Vulnerabilities: &[]insightapi.PackageVulnerability{v}}}
	got := Vulns(pkg)
	if len(got) != 1 || got[0].FixedIn != "6.7.3" || got[0].Risk != "HIGH" {
		t.Fatalf("got %+v", got)
	}
}
