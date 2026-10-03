package license

import (
	"context"
	"testing"

	"github.com/depguard/depguard/internal/scan"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

func TestNonStandardLicenseIsMediumNonBlocking(t *testing.T) {
	pkg := &models.Package{Manifest: models.NewPackageManifestFromLocal("x", models.EcosystemPyPI)}
	pkg.Name, pkg.Version = "idna", "2.7"
	lic := []insightapi.License{"non-standard"}
	pkg.Insights = &insightapi.PackageVersionInsight{Licenses: &lic}
	fs, _ := New(Config{}).Check(context.Background(), scan.CheckInput{
		Project: scan.Project{License: "MIT", UsageModel: scan.UsageDistributedBinary}, Packages: []*models.Package{pkg}})
	if len(fs) != 1 || fs[0].Rule != RuleUnknown || fs[0].Severity != scan.SeverityMedium || fs[0].Blocking {
		t.Fatalf("got %+v", fs)
	}
}
