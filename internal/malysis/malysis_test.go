package malysis

import (
	"context"
	"os"
	"testing"

	"github.com/safedep/vet/pkg/models"
)

// TestLiveCommunityService talks to community-api.safedep.io; run with MALYSIS_LIVE=1.
func TestLiveCommunityService(t *testing.T) {
	if os.Getenv("MALYSIS_LIVE") == "" {
		t.Skip("set MALYSIS_LIVE=1 to query the live service")
	}
	c, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name, version string) *models.Package {
		p := &models.Package{Manifest: models.NewPackageManifestFromLocal("x", models.EcosystemNpm)}
		p.Name, p.Version = name, version
		return p
	}
	bad, good := mk("flatmap-stream", "0.1.1"), mk("lodash", "4.17.21")
	got := c.Query(context.Background(), []*models.Package{bad, good})
	t.Logf("flatmap-stream: %+v", got[bad])
	t.Logf("lodash: %+v", got[good])
	if got[good].Malware {
		t.Error("lodash flagged")
	}
}
