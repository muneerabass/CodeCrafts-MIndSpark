package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// riskSeed is tenant "tr": an MIT project whose app → express → body-parser → qs
// chain carries a KEV advisory (fixed_in from OSV ranges; body-parser's LOW one has a stored fixed_in), plus a typosquat, a deprecated dev dependency and
// a GPL dependency.
const riskSeed = `
INSERT INTO tenant_settings (tenant_id, domain) VALUES ('tr','r.test');
INSERT INTO projects (id, tenant_id, source, name, license, license_source) VALUES ('pr','tr','cli','risky','MIT','manifest');
INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('vr','tr','pr','main');
INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status, components_count)
  VALUES ('sr','tr','pr','vr','cli','success',6);
UPDATE project_versions SET last_scan_id = 'sr' WHERE id = 'vr';
INSERT INTO components (id, tenant_id, ecosystem, name, version, purl, licenses) VALUES
  ('r-express','tr','npm','express','4.17.1','pkg:npm/express@4.17.1','{MIT}'),
  ('r-bp','tr','npm','body-parser','1.19.0','pkg:npm/body-parser@1.19.0','{MIT}'),
  ('r-qs','tr','npm','qs','6.7.0','pkg:npm/qs@6.7.0','{BSD-3-Clause}'),
  ('r-lodahs','tr','npm','lodahs','1.0.0','pkg:npm/lodahs@1.0.0','{}'),
  ('r-request','tr','npm','request','2.88.2','pkg:npm/request@2.88.2','{Apache-2.0}'),
  ('r-gpl','tr','npm','gpl-lib','2.0.0','pkg:npm/gpl-lib@2.0.0','{GPL-3.0-only}');
INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path, direct, depth, dev) VALUES
  ('tr','vr','r-express','package-lock.json',true,1,false), ('tr','vr','r-bp','package-lock.json',false,2,false),
  ('tr','vr','r-qs','package-lock.json',false,2,false), ('tr','vr','r-lodahs','package-lock.json',true,1,false),
  ('tr','vr','r-request','package-lock.json',true,1,true), ('tr','vr','r-gpl','package-lock.json',false,2,false);
INSERT INTO project_version_dependencies (tenant_id, project_version_id, manifest_path, parent_component_id, child_component_id) VALUES
  ('tr','vr','package-lock.json',NULL,'r-express'), ('tr','vr','package-lock.json','r-express','r-bp'),
  ('tr','vr','package-lock.json','r-bp','r-qs'), ('tr','vr','package-lock.json','r-express','r-qs'),
  ('tr','vr','package-lock.json',NULL,'r-lodahs'), ('tr','vr','package-lock.json',NULL,'r-request'),
  ('tr','vr','package-lock.json','r-express','r-gpl');
INSERT INTO advisory (id, source, summary, details, risk, published, modified, raw) VALUES
  ('GHSA-qs','npm','qs prototype pollution','','HIGH', now(), now(), '{}');
INSERT INTO advisory_alias VALUES ('GHSA-qs','CVE-2022-24999');
INSERT INTO cve_score (cve, epss, kev) VALUES ('CVE-2022-24999', 0.42, true);
INSERT INTO affected (advisory_id, ecosystem, name_norm, ranges) VALUES ('GHSA-qs','npm','qs',
  '[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"6.2.4"}]},{"type":"SEMVER","events":[{"introduced":"6.7.0"},{"fixed":"6.7.3"}]}]');
INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk) VALUES ('tr','r-qs','GHSA-qs','HIGH');
INSERT INTO advisory (id, source, summary, details, risk, published, modified, raw) VALUES
  ('GHSA-bp','npm','body-parser DoS','','LOW', now(), now(), '{}');
INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk, fixed_in) VALUES ('tr','r-bp','GHSA-bp','LOW','1.20.3');
INSERT INTO scan_packages (tenant_id, scan_id, component_id, manifest_path, vulnerable, direct, depth, dev, via, paths, graph_source, imported) VALUES
  ('tr','sr','r-qs','package-lock.json',true,false,2,false,'{express@4.17.1,qs@6.7.0}',
     '[["express@4.17.1","qs@6.7.0"],["express@4.17.1","body-parser@1.19.0","qs@6.7.0"]]','lockfile',true),
  ('tr','sr','r-express','package-lock.json',false,true,1,false,'{express@4.17.1}','[]','lockfile',true),
  ('tr','sr','r-lodahs','package-lock.json',false,true,1,false,'{lodahs@1.0.0}','[]','lockfile',NULL),
  ('tr','sr','r-gpl','package-lock.json',false,false,2,false,'{express@4.17.1,gpl-lib@2.0.0}','[]','lockfile',NULL);
INSERT INTO policy_violations (id, tenant_id, scan_id, project_version_id, component_id, rule_name, category, summary, severity, blocking, details) VALUES
  ('rv1','tr','sr','vr','r-qs','vulnerability-high-or-higher','vulnerability','High vulnerability','high',true,'{}'),
  ('rv2','tr','sr','vr','r-lodahs','typosquat','suspicious','Name looks like lodash','high',true,'{"similar_to":"lodash"}'),
  ('rv3','tr','sr','vr','r-request','deprecated','suspicious','Package is deprecated','medium',false,'{"reason":"request has been deprecated"}'),
  ('rv4','tr','sr','vr','r-gpl','license-incompatible','license','GPL-3.0-only is incompatible with MIT','high',true,'{"license":"GPL-3.0-only"}');`

func mapOf(v any) map[string]any { return v.(map[string]any) }
func listOf(v any) []any         { return v.([]any) }

func TestAttackPaths(t *testing.T) {
	m := token("tr", "member", false)
	g := expect(t, do(t, "GET", "/api/v1/projects/pr/versions/vr/paths", m, nil), 200).body
	paths, nodes, edges := listOf(g["paths"]), listOf(g["nodes"]), listOf(g["edges"])
	if g["source"] != "lockfile" || len(paths) != 5 || len(nodes) != 5 || len(edges) != 6 || g["truncated"] != false {
		t.Fatalf("graph: %v", g)
	}
	top := mapOf(paths[0])
	adv := mapOf(listOf(top["advisories"])[0])
	if top["score"].(float64) != 55 || top["depth"].(float64) != 2 || top["direct_head"] != "express@4.17.1" ||
		top["risk"] != "HIGH" || top["imported"] != true || mapOf(top["target"])["name"] != "qs" ||
		adv["fixed_in"] != "6.7.3" || adv["kev"] != true || adv["epss"].(float64) < 0.41 ||
		!strings.HasPrefix(top["fix"].(string), "Upgrade qs to ≥6.7.3 (via express") {
		t.Fatalf("top path: %v", top)
	}
	for _, n := range nodes {
		n := mapOf(n)
		if n["name"] == "qs" && (n["vulns"].(float64) != 1 || n["max_risk"] != "HIGH" || n["direct"] != false) {
			t.Fatalf("qs node: %v", n)
		}
		if n["name"] == "lodahs" && n["suspicious"] != true {
			t.Fatalf("lodahs node: %v", n)
		}
	}
	if last := mapOf(paths[4]); mapOf(listOf(last["advisories"])[0])["fixed_in"] != "1.20.3" || // stored fixed_in
		last["fix"] != "Upgrade body-parser to ≥1.20.3 (via express: update express or pin body-parser with an override/resolution)" {
		t.Fatalf("stored fixed_in path: %v", last)
	}
	if e := mapOf(edges[0]); e["from"] != "app" || e["to"] != "r-express" {
		t.Fatalf("first edge: %v", e)
	}
	for q, want := range map[string]int{"?target=r-qs": 2, "?advisory=GHSA-qs": 2, "?target=r-lodahs": 1, "?advisory=nope": 0} {
		if g := expect(t, do(t, "GET", "/api/v1/projects/pr/versions/vr/paths"+q, m, nil), 200).body; len(listOf(g["paths"])) != want {
			t.Errorf("%s: %v", q, g["paths"])
		}
	}

	sp := listOf(expect(t, do(t, "GET", "/api/v1/scans/sr/paths", m, nil), 200).body["paths"])
	if len(sp) != 3 {
		t.Fatalf("scan paths: %v", sp)
	}
	chain := listOf(mapOf(sp[0])["chain"])
	if mapOf(chain[0])["component_id"] != "r-express" || mapOf(sp[0])["score"].(float64) != 55 {
		t.Fatalf("scan path: %v", sp[0])
	}
	vp := listOf(expect(t, do(t, "GET", "/api/v1/vulnerabilities/GHSA-qs/paths", m, nil), 200).body["items"])
	if len(vp) != 1 || mapOf(mapOf(vp[0])["project"])["name"] != "risky" || len(listOf(mapOf(vp[0])["paths"])) != 2 {
		t.Fatalf("vuln paths: %v", vp)
	}

	// Tenant isolation.
	a := token("ta", "owner", false)
	expect(t, do(t, "GET", "/api/v1/projects/pr/versions/vr/paths", a, nil), 404)
	expect(t, do(t, "GET", "/api/v1/projects/pr/versions/vr/licenses", a, nil), 404)
	expect(t, do(t, "GET", "/api/v1/projects/pr/settings", a, nil), 404)
	expect(t, do(t, "PUT", "/api/v1/projects/pr/settings", a, map[string]any{"usage_model": "saas"}), 404)
	expect(t, do(t, "GET", "/api/v1/scans/sr/report", a, nil), 404)
	if r := expect(t, do(t, "GET", "/api/v1/scans/sr/paths", a, nil), 404); r.code != 404 {
		t.Fatal("scan paths leak")
	}
	if v := expect(t, do(t, "GET", "/api/v1/vulnerabilities/GHSA-qs/paths", a, nil), 200).body; len(listOf(v["items"])) != 0 {
		t.Fatalf("vuln paths leak: %v", v)
	}
}

func TestRiskLists(t *testing.T) {
	m := token("tr", "member", false)
	for path, want := range map[string]float64{
		"/api/v1/components?direct=true":                           3,
		"/api/v1/components?direct=false":                          3,
		"/api/v1/projects/pr/versions/vr/components?direct=false":  3,
		"/api/v1/policy/violations?category=suspicious":            2,
		"/api/v1/policy/violations?category=license":               1,
		"/api/v1/policy/violations?severity=medium":                1,
		"/api/v1/projects/pr/versions/vr/violations?severity=high": 3,
	} {
		r := do(t, "GET", path, m, nil)
		if r.code != 200 || r.body["total"].(float64) != want {
			t.Errorf("%s: %d total=%v want %v: %s", path, r.code, r.body["total"], want, r.raw)
		}
	}
	expect(t, do(t, "GET", "/api/v1/components?direct=maybe", m, nil), 400)
	c := items(expect(t, do(t, "GET", "/api/v1/projects/pr/versions/vr/components?name=request", m, nil), 200))
	if c[0]["direct"] != true || c[0]["depth"].(float64) != 1 || c[0]["dev"] != true {
		t.Fatalf("component dependency fields: %v", c)
	}
	v := items(expect(t, do(t, "GET", "/api/v1/policy/violations?rule=typosquat", m, nil), 200))
	if v[0]["severity"] != "high" || v[0]["blocking"] != true || mapOf(v[0]["details"])["similar_to"] != "lodash" {
		t.Fatalf("violation fields: %v", v)
	}
	d := expect(t, do(t, "GET", "/api/v1/dashboard", m, nil), 200).body
	if d["transitive_vulnerabilities"].(float64) != 2 || d["attack_paths"].(float64) != 4 ||
		d["suspicious_findings"].(float64) != 2 || d["license_issues"].(float64) != 1 {
		t.Fatalf("dashboard: %v", d)
	}
	sc := expect(t, do(t, "GET", "/api/v1/scans/sr", m, nil), 200).body
	if len(listOf(sc["findings"])) != 3 {
		t.Fatalf("scan findings: %v", sc["findings"])
	}
	for _, p := range listOf(sc["packages"]) {
		p := mapOf(p)
		if mapOf(p["component"])["name"] == "qs" && (p["direct"] != false || p["depth"].(float64) != 2 ||
			len(listOf(p["via"])) != 2 || len(listOf(p["paths"])) != 2 || p["imported"] != true || p["graph_source"] != "lockfile") {
			t.Fatalf("scan package: %v", p)
		}
	}
	if d := expect(t, do(t, "GET", "/api/v1/dashboard", token("ta", "member", false), nil), 200).body; d["license_issues"].(float64) != 0 {
		t.Fatalf("dashboard leak: %v", d)
	}
}

func TestReport(t *testing.T) {
	m := token("tr", "member", false)
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/scans/sr/report?format=html", nil)
	req.Header.Set("Authorization", "Bearer "+m)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Disposition") != `attachment; filename="depguard-report-sr.html"` ||
		!strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("html report: %d %v", res.StatusCode, res.Header)
	}
	md := expect(t, do(t, "GET", "/api/v1/scans/sr/report", m, nil), 200).raw
	for _, want := range []string{"## 1. Summary", "## 3. Transitive vulnerabilities", "app → express@4.17.1 → qs@6.7.0",
		"looks like lodash", "Project license: MIT (manifest) · Usage model: distributed as a binary", "## 6. Attack paths",
		"Upgrade qs to ≥6.7.3", "## 7. Recommended next steps"} {
		if !strings.Contains(md, want) {
			t.Errorf("md report missing %q:\n%s", want, md)
		}
	}
	var j struct {
		Counts  map[string]float64 `json:"counts"`
		Verdict string             `json:"verdict"`
		Paths   []any              `json:"paths"`
	}
	raw := expect(t, do(t, "GET", "/api/v1/scans/sr/report?format=json", m, nil), 200).raw
	if err := json.Unmarshal([]byte(raw), &j); err != nil || j.Verdict != "fail" || j.Counts["transitive_vulnerabilities"] != 1 /* bp is not in the scan */ ||
		j.Counts["license_issues"] != 1 || j.Counts["suspicious"] != 2 || len(j.Paths) != 3 {
		t.Fatalf("json report: %v %s", err, raw)
	}
	expect(t, do(t, "GET", "/api/v1/scans/sr/report?format=pdf", m, nil), 400)
	expect(t, do(t, "GET", "/v1/scans/sr/report?format=md", apiKey(t, "tr"), nil), 200)
	expect(t, do(t, "GET", "/v1/scans/sr/report", apiKey(t, "ta"), nil), 404)
}

func TestProjectSettingsAndLicenses(t *testing.T) {
	m, a := token("tr", "member", false), token("tr", "admin", false)
	l := expect(t, do(t, "GET", "/api/v1/projects/pr/versions/vr/licenses", m, nil), 200).body
	if l["project_license"] != "MIT" || l["usage_model"] != "distributed_binary" || len(listOf(l["findings"])) != 1 {
		t.Fatalf("licenses: %v", l)
	}
	cats := map[string]string{}
	for _, d := range listOf(l["distribution"]) {
		d := mapOf(d)
		cats[d["license"].(string)] = d["category"].(string)
	}
	if cats["GPL-3.0-only"] != "strong_copyleft" || cats["MIT"] != "permissive" || cats["UNKNOWN"] != "unknown" {
		t.Fatalf("distribution: %v", l["distribution"])
	}
	expect(t, do(t, "GET", "/api/v1/projects/pr/versions/vb/licenses", m, nil), 404)

	s := expect(t, do(t, "GET", "/api/v1/projects/pr/settings", m, nil), 200).body
	if s["license"] != "MIT" || s["detected_license"] != "MIT" || s["license_source"] != "manifest" || s["usage_model"] != "distributed_binary" {
		t.Fatalf("settings: %v", s)
	}
	expect(t, do(t, "PUT", "/api/v1/projects/pr/settings", m, map[string]any{"usage_model": "saas"}), 403)
	expect(t, do(t, "PUT", "/api/v1/projects/pr/settings", a, map[string]any{"usage_model": "everywhere"}), 400)
	expect(t, do(t, "PUT", "/api/v1/projects/pr/settings", a, map[string]any{"license": "MIT; DROP TABLE"}), 400)
	s = expect(t, do(t, "PUT", "/api/v1/projects/pr/settings", a, map[string]any{"license": "(Apache-2.0 OR MIT)", "usage_model": "saas"}), 200).body
	if s["license"] != "(Apache-2.0 OR MIT)" || s["license_source"] != "override" || s["detected_license"] != nil || s["usage_model"] != "saas" {
		t.Fatalf("settings put: %v", s)
	}
	s = expect(t, do(t, "PUT", "/api/v1/projects/pr/settings", a, map[string]any{"license": nil, "license_source": "override"}), 200).body
	if s["license"] != nil || s["license_source"] != nil || s["usage_model"] != "saas" {
		t.Fatalf("settings clear: %v", s)
	}
	expect(t, do(t, "PUT", "/api/v1/projects/nope/settings", a, map[string]any{"usage_model": "saas"}), 404)
}

func TestPolicyRiskPresets(t *testing.T) {
	m, a := token("tr", "member", false), token("tr", "admin", false)
	p := expect(t, do(t, "GET", "/api/v1/policy", m, nil), 200).body
	pre := mapOf(p["presets"])
	sus, lic := mapOf(pre["suspicious"]), mapOf(pre["license"])
	if sus["typosquat"] != true || sus["unmaintained_months"].(float64) != 24 || len(listOf(sus["blocking"])) != 2 ||
		lic["enabled"] != true || lic["blocking_severity"] != "high" || len(listOf(lic["deny"])) != 0 || sus["no_source_repo"] != false {
		t.Fatalf("defaults: %v", pre)
	}
	sus["unmaintained_months"], sus["blocking"], sus["new_package"] = 12, []string{"typosquat"}, false
	lic["blocking_severity"] = "medium"
	expect(t, do(t, "PUT", "/api/v1/policy", a, p), 200)
	got := mapOf(expect(t, do(t, "GET", "/api/v1/policy", m, nil), 200).body["presets"])
	if s := mapOf(got["suspicious"]); s["unmaintained_months"].(float64) != 12 || s["new_package"] != false ||
		len(listOf(s["blocking"])) != 1 || mapOf(got["license"])["blocking_severity"] != "medium" {
		t.Fatalf("round trip: %v", got)
	}
	sus["blocking"] = []string{"nope"}
	expect(t, do(t, "PUT", "/api/v1/policy", a, p), 400)
	sus["blocking"], lic["blocking_severity"] = []string{}, "severe"
	expect(t, do(t, "PUT", "/api/v1/policy", a, p), 400)
}

func TestUploadProjectSettings(t *testing.T) {
	key := apiKey(t, "tr")
	f := map[string][]byte{"package-lock.json": []byte("{}"), "package.json": []byte("{}"), "LICENSE": []byte("MIT")}
	expect(t, do(t, "POST", "/v1/scans", key, lockfiles(map[string]string{"project": "up", "usage_model": "everywhere"}, f)), 400)
	expect(t, do(t, "POST", "/v1/scans", key, lockfiles(map[string]string{"project": "up", "project_license": "<b>"}, f)), 400)
	expect(t, do(t, "POST", "/v1/scans", key, lockfiles(map[string]string{"project": "up", "project_license": "Apache-2.0", "usage_model": "internal"}, f)), 202)
	var lic, src, usage string
	var n int
	ctx := context.Background()
	tdb.Owner.QueryRow(ctx, `SELECT license, license_source, usage_model FROM projects WHERE tenant_id = 'tr' AND name = 'up'`).Scan(&lic, &src, &usage)
	tdb.Owner.QueryRow(ctx, `SELECT count(*) FROM scan_uploads u JOIN scans s ON s.id = u.scan_id JOIN projects p ON p.id = s.project_id WHERE p.name = 'up'`).Scan(&n)
	if lic != "Apache-2.0" || src != "override" || usage != "internal" || n != 3 {
		t.Fatalf("upload settings: %q %q %q uploads=%d", lic, src, usage, n)
	}
}
