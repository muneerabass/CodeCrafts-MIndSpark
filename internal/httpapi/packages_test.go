package httpapi

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/depguard/depguard/internal/engine"
	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/pkgrules"
	"github.com/depguard/depguard/internal/scan"
)

// checkDeps is the pre-install checker over the test database: OSV matching
// from the local mirror and package rules (no network: deps.dev, Scorecard and
// SafeDep malware analysis are off).
func checkDeps() engine.Deps {
	e := enrich.New(tdb.App, enrich.Options{DisableDepsDev: true, DisableScorecard: true})
	return engine.Deps{Pool: tdb.App, Enricher: e, Checkers: func(p scan.PolicyConfig, _ scan.Project) []scan.Checker {
		if p.Presets == nil {
			return nil
		}
		return []scan.Checker{pkgrules.New(p.Presets.Packages)}
	}}
}

func TestPackageCheck(t *testing.T) {
	ctx := context.Background()
	_, err := tdb.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain, block_mode, policy) VALUES ('tg','g.test', true,
  '{"presets":{"vulnerability":{"min_risk":"HIGH"},"malware":{"enabled":true},"packages":[
     {"ecosystem":"npm","name":"lodash","versions":">=4.17.21","reason":"security baseline"},
     {"name":"request","deny":true,"reason":"deprecated"}]}}');
INSERT INTO advisory (id, source, summary, details, risk, published, modified, raw) VALUES
  ('GHSA-lodash','npm','prototype pollution','', 'HIGH', now(), now(), '{}'),
  ('MAL-evil','npm','malicious package','', 'CRITICAL', now(), now(), '{}');
INSERT INTO affected (advisory_id, ecosystem, name_norm, versions, ranges) VALUES
  ('GHSA-lodash','npm','lodash','{}','[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]'),
  ('MAL-evil','npm','evil-pkg','{1.0.0}','[]');`)
	if err != nil {
		t.Fatal(err)
	}
	owner := token("tg", "owner", false)
	key := expect(t, do(t, "POST", "/api/v1/api-keys", owner, map[string]any{"name": "laptop"}), 201).body["key"].(string)

	me := expect(t, do(t, "GET", "/v1/me", key, nil), 200).body
	if me["domain"] != "g.test" || me["block_mode"] != true || me["policy"].(map[string]any)["package_rules"].(float64) != 2 {
		t.Fatalf("me: %v", me)
	}

	pkgs := []map[string]any{
		{"ecosystem": "npm", "name": "lodash", "version": "4.17.15", "direct": true},
		{"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
		{"ecosystem": "npm", "name": "evil-pkg", "version": "1.0.0"},
		{"ecosystem": "npm", "name": "request", "version": "2.88.2"},
		{"ecosystem": "npm", "name": "left-pad", "version": "1.3.0"},
	}
	repoRules := []map[string]any{{"ecosystem": "npm", "name": "left-pad", "deny": true, "severity": "medium"}, {"name": "request", "allow": true}}
	check := func(bearer string, body map[string]any) (string, map[string]map[string]any) {
		t.Helper()
		r := expect(t, do(t, "POST", "/v1/packages/check", bearer, body), 200)
		by := map[string]map[string]any{}
		for _, p := range r.body["packages"].([]any) {
			m := p.(map[string]any)
			var rules []string
			for _, f := range m["findings"].([]any) {
				rules = append(rules, f.(map[string]any)["rule"].(string))
			}
			slices.Sort(rules)
			m["rules"] = strings.Join(rules, ",")
			by[m["name"].(string)+"@"+m["version"].(string)] = m
		}
		return r.body["decision"].(string), by
	}

	dec, by := check(key, map[string]any{"packages": pkgs, "repo_rules": repoRules})
	if dec != "block" || len(by) != 4 {
		t.Fatalf("decision %s, packages %v", dec, by)
	}
	for name, want := range map[string][2]string{
		"lodash@4.17.15": {"block", "version-not-allowed,vulnerability-high-or-higher"},
		"evil-pkg@1.0.0": {"block", "malicious-package"},
		"request@2.88.2": {"block", "package-denied"}, // a repo allow rule cannot loosen a team deny
		"left-pad@1.3.0": {"warn", "package-denied"},  // repo rule, medium = warning
	} {
		if got := by[name]; got == nil || got["decision"] != want[0] || got["rules"] != want[1] {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	if f := by["lodash@4.17.15"]["findings"].([]any); !slices.ContainsFunc(f, func(x any) bool { return x.(map[string]any)["fixed_in"] == "4.17.21" }) {
		t.Errorf("fixed_in missing: %v", f)
	}

	// Warn mode: policy violations warn, malware still blocks.
	if _, err := tdb.Owner.Exec(ctx, `UPDATE tenant_settings SET block_mode=false WHERE tenant_id='tg'`); err != nil {
		t.Fatal(err)
	}
	_, by = check(key, map[string]any{"packages": pkgs})
	if by["lodash@4.17.15"]["decision"] != "warn" || by["evil-pkg@1.0.0"]["decision"] != "block" {
		t.Errorf("warn mode: %v", by)
	}

	// Exclusions hide a package's findings (never malware).
	if _, err := tdb.Owner.Exec(ctx, `INSERT INTO exclusions (id, tenant_id, ecosystem, name, reason, created_by) VALUES
		('ex-req','tg','npm','request','accepted','u'), ('ex-evil','tg','npm','evil-pkg','nope','u')`); err != nil {
		t.Fatal(err)
	}
	_, by = check(key, map[string]any{"packages": pkgs})
	if by["request@2.88.2"] != nil || by["evil-pkg@1.0.0"] == nil {
		t.Errorf("exclusions: %v", by)
	}

	// Lockfile diff: only packages new in "after" are checked, direct from package.json.
	lock := func(deps ...string) string {
		s := `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","version":"1.0.0"}`
		for _, d := range deps {
			n, v, _ := strings.Cut(d, "@")
			s += `,"node_modules/` + n + `":{"version":"` + v + `"}`
		}
		return s + `}}`
	}
	r := expect(t, do(t, "POST", "/v1/packages/check", key, map[string]any{
		"before":    []map[string]string{{"path": "package-lock.json", "content": lock("left-pad@1.3.0")}},
		"after":     []map[string]string{{"path": "package-lock.json", "content": lock("left-pad@1.3.0", "lodash@4.17.15")}},
		"manifests": []map[string]string{{"path": "package.json", "content": `{"dependencies":{"left-pad":"1.3.0","lodash":"4.17.15"}}`}},
	}), 200).body
	ps := r["packages"].([]any)
	if r["checked"].(float64) != 1 || len(ps) != 1 || ps[0].(map[string]any)["name"] != "lodash" || ps[0].(map[string]any)["direct"] != true {
		t.Errorf("lockfile diff: %v", r)
	}

	// Tenant isolation: tenant b has no package rules.
	keyB := expect(t, do(t, "POST", "/api/v1/api-keys", token("tb", "owner", false), map[string]any{"name": "b"}), 201).body["key"].(string)
	_, by = check(keyB, map[string]any{"packages": []map[string]any{{"ecosystem": "npm", "name": "request", "version": "2.88.2"}}})
	if len(by) != 0 {
		t.Errorf("tenant b sees tenant c rules: %v", by)
	}
	expect(t, do(t, "POST", "/v1/packages/check", keyB, map[string]any{"packages": []map[string]any{{"ecosystem": "cobol", "name": "x", "version": "1"}}}), 400)
	expect(t, do(t, "POST", "/v1/packages/check", "", map[string]any{"packages": pkgs}), 401)
}
