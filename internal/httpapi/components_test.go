package httpapi

import (
	"context"
	"testing"
)

func TestComponentHealthAndDetail(t *testing.T) {
	ctx := context.Background()
	_, err := tdb.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain) VALUES ('tc','c.test'), ('tc2','c2.test');
INSERT INTO projects (id, tenant_id, source, name, url) VALUES ('pc','tc','cli','acme/api','');
INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('vc','tc','pc','main');
INSERT INTO components (id, tenant_id, ecosystem, name, version, purl, licenses) VALUES
  ('hc1','tc','PyPI','Requests','2.31.0','pkg:pypi/requests@2.31.0','{Apache-2.0}'), ('hc2','tc','npm','evilpkg','1.0.0','pkg:npm/evilpkg@1.0.0','{}'),
  ('hc3','tc','npm','nometa','1.0.0','pkg:npm/nometa@1.0.0','{}');
INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path, direct) VALUES ('tc','vc','hc1','requirements.txt',true);
INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk, fixed_in) VALUES ('tc','hc2','MAL-2026-9','CRITICAL',NULL), ('tc','hc1','GHSA-r1','MEDIUM','2.32.0');
INSERT INTO package_meta (ecosystem, name_norm, version, repo, stars, forks, published_at) VALUES ('PyPI','requests','2.31.0','github.com/psf/requests', 52000, 9000, now() - interval '400 days');
INSERT INTO package_latest (ecosystem, name_norm, default_version, latest_published, first_published, deprecated) VALUES ('PyPI','requests','2.32.3', now() - interval '60 days', now() - interval '14 years', false);
INSERT INTO scorecard (repo, score, checks) VALUES ('github.com/psf/requests', 7.5, '{"Maintained":10,"Code-Review":8}');`)
	if err != nil {
		t.Fatal(err)
	}
	member := token("tc", "member", false)
	h := expect(t, do(t, "GET", "/api/v1/components/health?ids=hc1,hc2,hc3,other", member, nil), 200).body
	r1, r2, r3 := mapOf(h["hc1"]), mapOf(h["hc2"]), mapOf(h["hc3"])
	// requests: scorecard .75*40=30, recency 20, popularity 15, repo 10, not deprecated 10, age 5 → 9.0
	if r1["score"].(float64) != 9 || r1["level"] != "good" || r2["level"] != "malicious" || r3["score"] != nil || r3["level"] != "unknown" || h["other"] != nil {
		t.Fatalf("health %v", h)
	}
	expect(t, do(t, "GET", "/api/v1/components/health?ids=hc1", token("tc2", "member", false), nil), 200) // other tenant: empty map
	if b := do(t, "GET", "/api/v1/components/health?ids=hc1", token("tc2", "member", false), nil).body; len(b) != 0 {
		t.Fatalf("other tenant sees %v", b)
	}

	d := expect(t, do(t, "GET", "/api/v1/components/hc1", member, nil), 200).body
	meta, sc := mapOf(d["meta"]), mapOf(d["scorecard"])
	if d["name"] != "Requests" || meta["repo"] != "github.com/psf/requests" || meta["default_version"] != "2.32.3" || sc["score"].(float64) != 7.5 ||
		mapOf(sc["checks"])["Maintained"].(float64) != 10 || len(listOf(d["vulns"])) != 1 || len(listOf(d["projects"])) != 1 || mapOf(d["health"])["level"] != "good" {
		t.Fatalf("detail %v", d)
	}
	expect(t, do(t, "GET", "/api/v1/components/hc1", token("tc2", "member", false), nil), 404)
}
