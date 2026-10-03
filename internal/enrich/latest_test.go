package enrich_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds/feedstest"
	"github.com/safedep/vet/pkg/models"
)

func TestPackageLatest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/v3/systems/npm/packages/request":
			w.Write([]byte(`{"versions":[
				{"versionKey":{"version":"2.88.0"},"publishedAt":"2019-01-01T00:00:00Z","isDeprecated":true},
				{"versionKey":{"version":"2.88.2"},"publishedAt":"2020-02-11T16:47:41Z","isDefault":true,"isDeprecated":true}]}`))
		case "/v3/systems/npm/packages/request/versions/2.88.2":
			w.Write([]byte(`{"isDeprecated":true,"deprecatedReason":"request has been deprecated"}`))
		case "/v3/systems/pypi/packages/Flask":
			w.Write([]byte(`{"versions":[
				{"versionKey":{"version":"3.1.0"},"publishedAt":"2024-11-13T00:00:00Z","isDefault":true},
				{"versionKey":{"version":"0.1"},"publishedAt":"2010-04-16T00:00:00Z","isDeprecated":true}]}`))
		case "/v3/systems/npm/packages/flaky":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	pool := feedstest.Postgres(t)
	ctx := context.Background()
	e := enrich.New(pool, enrich.Options{DepsDevURL: srv.URL, DisableScorecard: true})

	l, err := e.PackageLatest(ctx, "npm", "request")
	if err != nil {
		t.Fatal(err)
	}
	if !l.Found || l.DefaultVersion != "2.88.2" || !l.Deprecated || l.DeprecatedReason != "request has been deprecated" ||
		l.LatestPublished == nil || l.LatestPublished.Year() != 2020 || !slices.Equal(l.DeprecatedVersions, []string{"2.88.0", "2.88.2"}) {
		t.Fatalf("request = %+v", l)
	}

	flask := pkg(models.EcosystemPyPI, "Flask", "0.1")
	flask2 := pkg(models.EcosystemPyPI, "flask", "3.1.0")
	ghost := pkg(models.EcosystemNpm, "no-such-pkg", "1.0.0")
	flaky := pkg(models.EcosystemNpm, "flaky", "1.0.0")
	cargo := pkg(models.EcosystemPackagist, "a/b", "1.0.0") // no deps.dev system
	got := e.PackagesLatest(ctx, []*models.Package{flask, flask2, ghost, flaky, cargo})
	if l := got[flask]; l == nil || l.Deprecated || !l.VersionDeprecated("0.1") || l.VersionDeprecated("3.1.0") || got[flask2] != l {
		t.Fatalf("flask = %+v / %+v", got[flask], got[flask2])
	}
	if l := got[ghost]; l == nil || l.Found {
		t.Fatalf("404 = %+v", l)
	}
	if got[flaky] != nil || got[cargo] != nil {
		t.Fatalf("flaky/cargo = %+v %+v", got[flaky], got[cargo])
	}

	// Everything but the 5xx is cached (including the 404).
	before := hits.Load()
	got = enrich.New(pool, enrich.Options{DepsDevURL: srv.URL}).PackagesLatest(ctx, []*models.Package{flask, ghost, flaky})
	if n := hits.Load() - before; n != 1 || got[flask] == nil || got[ghost] == nil {
		t.Fatalf("second run: %d API calls, %+v", n, got)
	}

	// Disabled deps.dev still serves the cache; network errors surface on the single call.
	off := enrich.New(pool, enrich.Options{DepsDevURL: srv.URL, DisableDepsDev: true})
	if l, err := off.PackageLatest(ctx, "npm", "request"); err != nil || l == nil || !l.Deprecated {
		t.Fatalf("cached request = %+v, %v", l, err)
	}
	if l, err := off.PackageLatest(ctx, "npm", "unknown"); err != nil || l != nil {
		t.Fatalf("disabled miss = %+v, %v", l, err)
	}
	if _, err := e.PackageLatest(ctx, "npm", "flaky"); err == nil {
		t.Fatal("5xx not reported")
	}
}
