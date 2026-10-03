package suspicious

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds/feedstest"
	"github.com/depguard/depguard/internal/scan"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

func ptr[T any](v T) *T { return &v }

var now = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// pkg builds an enriched npm package; repo "" = no project, maintained < 0 = no scorecard.
func pkg(name, version, repo string, stars int, maintained float32) *models.Package {
	p := &models.Package{Manifest: models.NewPackageManifestFromLocal("package-lock.json", models.EcosystemNpm)}
	p.Name, p.Version = name, version
	ins := &insightapi.PackageVersionInsight{}
	if repo != "" {
		ins.Projects = &[]insightapi.PackageProjectInfo{{Name: ptr(repo), Stars: ptr(stars)}}
	}
	if maintained >= 0 {
		ins.Scorecard = &insightapi.Scorecard{Content: &insightapi.ScorecardContentV2{Score: ptr(float32(5)),
			Checks: &[]insightapi.ScorecardV2Check{{Name: ptr(insightapi.ScorecardV2CheckName("Maintained")), Score: ptr(maintained)}}}}
	}
	p.Insights = ins
	return p
}

func rules(fs []scan.Finding) (out []string) {
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func TestRules(t *testing.T) {
	cfg := ConfigFromPolicy(scan.PolicyConfig{})
	cfg.NoRepo = true
	c := &checker{cfg: cfg, now: func() time.Time { return now }}
	old := now.AddDate(-3, 0, 0)
	ancient := now.AddDate(-5, 0, 0)
	recent := now.AddDate(0, -2, 0)
	brandNew := now.AddDate(0, 0, -3)

	squat := pkg("lodahs", "1.0.0", "github.com/x/lodahs", 3, -1)
	starred := pkg("lodahs", "1.0.0", "github.com/x/lodahs", 5000, -1)
	deprecatedVer := pkg("left-pad-ish", "1.0.0", "github.com/x/l", 10, -1)
	deprecatedPkg := pkg("request-ish", "2.0.0", "github.com/x/r", 10, -1)
	staleUnmaintained := pkg("stale-pkg", "1.0.0", "github.com/x/s", 10, 0)
	staleMaintained := pkg("stale-but-ok", "1.0.0", "github.com/x/s", 10, 8)
	staleNoRepo := pkg("stale-norepo", "1.0.0", "", 0, -1)
	ancientNoRepo := pkg("ancient-norepo", "1.0.0", "", 0, -1)
	fresh := pkg("brand-new-pkg", "0.0.1", "github.com/x/n", 10, -1)
	newVersionOldPkg := pkg("established-lib", "9.0.0", "github.com/x/e", 10, -1) // new release of an old package

	f := facts{
		latest: map[*models.Package]*enrich.Latest{
			deprecatedVer:     {Found: true, LatestPublished: &recent, DeprecatedVersions: []string{"1.0.0"}},
			deprecatedPkg:     {Found: true, LatestPublished: &recent, Deprecated: true, DeprecatedReason: "use fetch"},
			staleUnmaintained: {Found: true, LatestPublished: &old},
			staleMaintained:   {Found: true, LatestPublished: &old},
			staleNoRepo:       {Found: true, LatestPublished: &old},
			ancientNoRepo:     {Found: true, LatestPublished: &ancient},
			fresh:             {Found: true, LatestPublished: &brandNew, FirstPublished: &brandNew},
			newVersionOldPkg:  {Found: true, LatestPublished: &brandNew, FirstPublished: &old},
		},
		published: map[*models.Package]time.Time{fresh: now.AddDate(0, 0, -3), deprecatedVer: old},
	}
	cases := []struct {
		p    *models.Package
		want []string
	}{
		{squat, []string{RuleTyposquat}},
		{starred, nil},
		{deprecatedVer, []string{RuleDeprecated}},
		{deprecatedPkg, []string{RuleDeprecated}},
		{staleUnmaintained, []string{RuleUnmaintained}},
		{staleMaintained, nil},
		{staleNoRepo, []string{RuleNoSourceRepo}}, // missing repo data alone is not evidence of abandonment
		{ancientNoRepo, []string{RuleUnmaintained, RuleNoSourceRepo}},
		{fresh, []string{RuleNewPackage}},
		{newVersionOldPkg, nil}, // a fresh release of an established package is not flagged
	}
	for _, tc := range cases {
		if got := rules(c.evaluate(tc.p, f)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %v want %v", tc.p.Name, got, tc.want)
		}
	}

	fs := c.evaluate(squat, f)
	if d := fs[0].Details; d["similar_to"] != "lodash" || d["technique"] != TechniqueSwap || !fs[0].Blocking ||
		fs[0].Severity != scan.SeverityHigh || fs[0].Category != scan.CategorySuspicious {
		t.Errorf("typosquat finding = %+v", fs[0])
	}
	fs = c.evaluate(deprecatedPkg, f)
	if fs[0].Details["reason"] != "use fetch" || fs[0].Blocking || fs[0].Severity != scan.SeverityMedium {
		t.Errorf("deprecated finding = %+v", fs[0])
	}
	fs = c.evaluate(staleUnmaintained, f)
	if fs[0].Details["maintained_score"] != float32(0) || fs[0].Details["latest_published"] != old.Format(time.RFC3339) {
		t.Errorf("unmaintained finding = %+v", fs[0].Details)
	}
}

func TestConfigFromPolicy(t *testing.T) {
	def := ConfigFromPolicy(scan.PolicyConfig{})
	if !def.Typosquat || !def.Unmaintained || def.NoRepo || def.UnmaintainedMonths != 24 ||
		!def.Blocking[RuleTyposquat] || !def.Blocking[RuleUnusualBehaviour] || def.Blocking[RuleDeprecated] {
		t.Fatalf("defaults = %+v", def)
	}
	pc, err := scan.ParsePolicy([]byte(`{"presets":{"suspicious":{"typosquat":false,"unmaintained_months":12,"blocking":["deprecated"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	c := ConfigFromPolicy(pc)
	if c.Typosquat || !c.Deprecated || c.UnmaintainedMonths != 12 || !c.Blocking[RuleDeprecated] || c.Blocking[RuleTyposquat] {
		t.Fatalf("config = %+v", c)
	}
}

func TestPrioritize(t *testing.T) {
	popular := pkg("popular", "1", "github.com/x/p", 9000, -1)
	norepo := pkg("norepo", "1", "", 0, -1)
	squat := pkg("squat", "1", "github.com/x/s", 9000, -1)
	dep := pkg("dep", "1", "github.com/x/d", 9000, -1)
	lowstars := pkg("lowstars", "1", "github.com/x/l", 3, -1)
	fs := []scan.Finding{{Rule: RuleDeprecated, Package: dep}, {Rule: RuleTyposquat, Package: squat}, {Rule: RuleUnmaintained, Package: popular}}
	var got []string
	for _, p := range Prioritize([]*models.Package{popular, norepo, squat, dep, lowstars}, fs) {
		got = append(got, p.Name)
	}
	if want := []string{"squat", "dep", "norepo", "lowstars", "popular"}; !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// TestCheckFromCache runs the checker against cached deps.dev data with
// deps.dev disabled: no network, data from package_latest / package_meta.
func TestCheckFromCache(t *testing.T) {
	pool := feedstest.Postgres(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO package_latest (ecosystem, name_norm, default_version, latest_published, deprecated, deprecated_versions, deprecated_reason)
		VALUES ('npm', 'request', '2.88.2', now() - interval '5 years', true, '{2.88.2}', 'request has been deprecated');
		INSERT INTO package_latest (ecosystem, name_norm, default_version, latest_published, first_published)
		VALUES ('npm', 'fresh-thing', '0.1.0', now() - interval '2 days', now() - interval '2 days');
		INSERT INTO package_meta (ecosystem, name_norm, version, published_at) VALUES ('npm', 'fresh-thing', '0.1.0', now() - interval '2 days')`)
	if err != nil {
		t.Fatal(err)
	}
	e := enrich.New(pool, enrich.Options{DisableDepsDev: true, DisableScorecard: true})
	pkgs := []*models.Package{pkg("request", "2.88.2", "", 0, -1), pkg("fresh-thing", "0.1.0", "github.com/x/f", 1, -1), pkg("expres", "1.0.0", "", 0, -1)}
	fs, err := New(pool, e, ConfigFromPolicy(scan.PolicyConfig{})).Check(ctx, scan.CheckInput{Packages: pkgs})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, f := range fs {
		got[f.Package.Name] = append(got[f.Package.Name], f.Rule)
	}
	want := map[string][]string{"request": {RuleDeprecated, RuleUnmaintained}, "fresh-thing": {RuleNewPackage}, "expres": {RuleTyposquat}}
	for n, w := range want {
		if !slices.Equal(got[n], w) {
			t.Errorf("%s: got %v want %v", n, got[n], w)
		}
	}
}
