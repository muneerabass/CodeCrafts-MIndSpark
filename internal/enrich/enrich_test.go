package enrich_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/feeds/feedstest"
	"github.com/depguard/depguard/internal/scan"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

var advisories = []string{
	`{"id":"MAL-2024-9","summary":"Malicious code in evil-pkg","modified":"2024-01-01T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"npm","name":"evil-pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	`{"id":"GHSA-high","summary":"ReDoS in lodash","aliases":["CVE-2021-23337"],"modified":"2024-01-01T00:00:00Z",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
	  "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`,
	`{"id":"GHSA-withdrawn","modified":"2024-01-01T00:00:00Z","withdrawn":"2024-01-02T00:00:00Z",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	  "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"versions":["4.17.20"]}]}`,
	`{"id":"GHSA-med","modified":"2024-01-01T00:00:00Z","database_specific":{"severity":"MODERATE"},
	  "affected":[{"package":{"ecosystem":"PyPI","name":"requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.31.0"}]}]}]}`,
	`{"id":"GHSA-log4shell","aliases":["CVE-2021-44228"],"modified":"2024-01-01T00:00:00Z",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
	  "affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},
	    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}]}]}`,
}

type fakeAPI struct {
	mu   sync.Mutex
	hits int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits++
	f.mu.Unlock()
	switch r.URL.Path {
	case "/v3/systems/npm/packages/lodash/versions/4.17.20", "/v3/systems/npm/packages/lodash/versions/4.17.21":
		w.Write([]byte(`{"licenses":["MIT"],"relatedProjects":[
			{"projectKey":{"id":"github.com/lodash/lodash"},"relationType":"ISSUE_TRACKER"},
			{"projectKey":{"id":"github.com/lodash/lodash"},"relationType":"SOURCE_REPO"}]}`))
	case "/v3/systems/pypi/packages/Requests/versions/2.30.0":
		w.Write([]byte(`{"licenses":["GPL-3.0-only"]}`))
	case "/v3/systems/npm/packages/@scope%2Fapp/versions/1.0.0:dependencies", "/v3/systems/npm/packages/@scope/app/versions/1.0.0:dependencies":
		w.Write([]byte(`{"nodes":[{"versionKey":{"system":"NPM","name":"@scope/app","version":"1.0.0"},"relation":"SELF"},
			{"versionKey":{"system":"NPM","name":"qs","version":"6.5.0"},"relation":"DIRECT"}],
			"edges":[{"fromNode":0,"toNode":1,"requirement":"^6"},{"fromNode":0,"toNode":9}]}`))
	case "/v3/projects/github.com/lodash/lodash":
		w.Write([]byte(`{"starsCount":100,"forksCount":10}`))
	case "/projects/github.com/lodash/lodash":
		w.Write([]byte(`{"score":6.8,"checks":[{"name":"Maintained","score":6},{"name":"Code-Review","score":3}]}`))
	default:
		http.NotFound(w, r)
	}
}

func pkg(eco, name, ver string) *models.Package {
	p := &models.Package{Manifest: models.NewPackageManifestFromLocal("x", eco)}
	p.Name, p.Version = name, ver
	return p
}

func TestEnrich(t *testing.T) {
	pool := feedstest.Postgres(t)
	ctx := context.Background()
	var raws [][]byte
	for _, a := range advisories {
		raws = append(raws, []byte(a))
	}
	if err := feeds.New(pool, feeds.Options{}).Ingest(ctx, "test", raws); err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{}
	srv := httptest.NewServer(api)
	defer srv.Close()
	opts := enrich.Options{DepsDevURL: srv.URL, ScorecardURL: srv.URL}

	lodash := pkg(models.EcosystemNpm, "lodash", "4.17.20")
	lodashFixed := pkg(models.EcosystemNpm, "lodash", "4.17.21")
	evil := pkg(models.EcosystemNpm, "Evil-Pkg", "1.0.0")
	requests := pkg(models.EcosystemPyPI, "Requests", "2.30.0")
	log4j := pkg(models.EcosystemMaven, "org.apache.logging.log4j:log4j-core", "2.14.1")
	crate := pkg(models.EcosystemCargo, "serde", "1.0.0")
	unknown := pkg("Terraform", "x", "1")
	pkgs := []*models.Package{lodash, lodashFixed, evil, requests, log4j, crate, unknown}

	if err := enrich.New(pool, opts).Enrich(ctx, pkgs); err != nil {
		t.Fatal(err)
	}

	ids := func(p *models.Package) (out []string) {
		for _, m := range enrich.Matches(p) {
			out = append(out, m.AdvisoryID+":"+m.Risk)
		}
		return out
	}
	for p, want := range map[*models.Package][]string{
		lodash:      {"GHSA-high:HIGH"}, // withdrawn excluded
		lodashFixed: nil,
		evil:        {"MAL-2024-9:CRITICAL"},
		requests:    {"GHSA-med:MEDIUM"},
		log4j:       {"GHSA-log4shell:CRITICAL"},
		crate:       nil,
		unknown:     nil,
	} {
		if got := ids(p); !slices.Equal(got, want) {
			t.Errorf("%s@%s matches = %v, want %v", p.Name, p.Version, got, want)
		}
	}
	if m := enrich.Matches(evil); !m[0].Malware {
		t.Errorf("MAL match not flagged as malware")
	}
	if m := enrich.Matches(lodash); m[0].FixedIn != "4.17.21" {
		t.Errorf("lodash FixedIn = %q", m[0].FixedIn)
	}

	// deps.dev dependency graph, cached (including not-found).
	e := enrich.New(pool, opts)
	graph := func() string {
		t.Helper()
		nodes, edges, err := e.DepsDevGraph(ctx, models.EcosystemNpm, "@scope/app", "1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprint(nodes, edges)
	}
	if g := graph(); g != "[{@scope/app 1.0.0 SELF} {qs 6.5.0 DIRECT}] [[0 1]]" {
		t.Errorf("deps.dev graph = %s", g)
	}
	if nodes, _, err := e.DepsDevGraph(ctx, "npm", "nope", "1.0.0"); err != nil || nodes != nil {
		t.Errorf("not found: %v %v", nodes, err)
	}
	gh := api.hits
	if g := graph(); g != "[{@scope/app 1.0.0 SELF} {qs 6.5.0 DIRECT}] [[0 1]]" || api.hits != gh {
		t.Errorf("cached graph = %s (%d new calls)", g, api.hits-gh)
	}
	if _, _, _ = e.DepsDevGraph(ctx, "npm", "nope", "1.0.0"); api.hits != gh {
		t.Errorf("not-found not cached")
	}

	v := (*lodash.Insights.Vulnerabilities)[0]
	if s := (*v.Severities)[0]; *s.Score != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" || *v.Summary != "ReDoS in lodash" ||
		!slices.Equal(*v.Aliases, []string{"CVE-2021-23337"}) {
		t.Errorf("lodash vuln = %+v", v)
	}
	checkMeta := func(label string) {
		t.Helper()
		ins := lodash.Insights
		if !slices.Equal(*ins.Licenses, []insightapi.License{"MIT"}) {
			t.Errorf("%s: licenses = %v", label, *ins.Licenses)
		}
		if ins.Projects == nil || *(*ins.Projects)[0].Name != "github.com/lodash/lodash" || *(*ins.Projects)[0].Stars != 100 ||
			*(*ins.Projects)[0].Forks != 10 || *(*ins.Projects)[0].Type != "GITHUB" {
			t.Errorf("%s: projects = %+v", label, ins.Projects)
		}
		if ins.Scorecard == nil || *ins.Scorecard.Content.Score != 6.8 || len(*ins.Scorecard.Content.Checks) != 2 {
			t.Errorf("%s: scorecard = %+v", label, ins.Scorecard)
		}
	}
	checkMeta("fresh")

	pol, err := scan.NewPolicy(scan.DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	rules := func(p *models.Package) (out []string) {
		vs, err := pol.Evaluate(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vs {
			out = append(out, v.Rule.Name)
		}
		return out
	}
	for p, want := range map[*models.Package][]string{
		lodash:      {"critical-or-high-vulnerability"},
		lodashFixed: nil,
		evil:        {"malicious-package"},
		requests:    nil, // licenses are checked by internal/license, not CEL
		log4j:       {"critical-or-high-vulnerability"},
		crate:       nil,
	} {
		if got := rules(p); !slices.Equal(got, want) {
			t.Errorf("%s@%s policy = %v, want %v", p.Name, p.Version, got, want)
		}
	}

	// Second run is served from the package_meta / scorecard cache.
	hits := api.hits
	lodash.Insights = nil
	if err := enrich.New(pool, opts).Enrich(ctx, pkgs); err != nil {
		t.Fatal(err)
	}
	if api.hits != hits {
		t.Errorf("cache miss: %d new API calls", api.hits-hits)
	}
	checkMeta("cached")

	// Network failures never fail the scan.
	srv.Close()
	axios := pkg(models.EcosystemNpm, "axios", "1.0.0")
	if err := enrich.New(pool, opts).Enrich(ctx, []*models.Package{axios}); err != nil {
		t.Fatalf("network failure surfaced: %v", err)
	}
	if axios.Insights == nil || axios.Insights.Projects != nil {
		t.Errorf("axios insights = %+v", axios.Insights)
	}
}
