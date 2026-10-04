package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/httpapi/pgtest"
	"github.com/depguard/depguard/internal/httpapi/riverdb"
	"github.com/depguard/depguard/internal/query"
	"github.com/golang-jwt/jwt/v5"
)

var (
	tdb    *pgtest.DB
	srv    *httptest.Server
	secret = []byte("s3cret")
)

func TestMain(m *testing.M) {
	if os.Getenv("SKIP_DB_TESTS") != "" {
		os.Exit(0)
	}
	ctx := context.Background()
	var err error
	if tdb, err = pgtest.Start(ctx); err != nil {
		panic(err)
	}
	jobs, err := riverdb.NewInserter(tdb.App)
	if err != nil {
		panic(err)
	}
	if err := seed(ctx); err != nil {
		panic(err)
	}
	srv = httptest.NewServer(New(Deps{
		Pool: tdb.App, Jobs: jobs, Query: &query.Executor{Pool: tdb.Query}, JWTSecret: secret,
		PublicURL: "https://app.test", APIKeyRPS: 1000, APIKeyBurst: 1000,
		GitHubInstallURL: func() string { return "https://github.com/apps/depguard/installations/new" },
		Redeliver:        func(context.Context, string) error { return nil },
		FeedsStatus:      func(context.Context) (any, error) { return []map[string]string{{"source": "osv:npm"}}, nil },
		CheckPackages:    checkDeps().CheckPackages,
	}))
	code := m.Run()
	srv.Close()
	tdb.Close()
	os.Exit(code)
}

func seed(ctx context.Context) error {
	_, err := tdb.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain) VALUES ('ta','a.test'), ('tb','b.test');
INSERT INTO projects (id, tenant_id, source, name, url) VALUES ('pa','ta','github','acme/web','https://github.com/acme/web'),
  ('pb','tb','cli','beta','');
INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('va','ta','pa','main'), ('vb','tb','pb','main');
INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status, components_count, vulns_count, violations_count, report_md)
  VALUES ('s1','ta','pa','va','push','success',2,1,1,'# report'), ('sb','tb','pb','vb','cli','success',0,0,0,NULL);
UPDATE project_versions SET last_scan_id = 's1' WHERE id = 'va';
INSERT INTO components (id, tenant_id, ecosystem, name, version, purl, licenses) VALUES
  ('c1','ta','npm','lodash','4.17.0','pkg:npm/lodash@4.17.0','{MIT}'),
  ('c2','ta','npm','evil','1.0.0','pkg:npm/evil@1.0.0','{}'),
  ('c3','ta','npm','gpl-thing','1.0.0','pkg:npm/gpl-thing@1.0.0','{GPL-3.0-only}');
INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path) VALUES
  ('ta','va','c1','package-lock.json'), ('ta','va','c2','package-lock.json');
INSERT INTO advisory (id, source, summary, details, risk, published, modified, raw) VALUES
  ('GHSA-1','npm','proto pollution','details','HIGH', now() - interval '3 days', now(), '{"references":[{"type":"WEB","url":"https://x"}]}'),
  ('MAL-1','npm','malicious','','CRITICAL', now(), now(), '{}');
INSERT INTO advisory_alias VALUES ('GHSA-1','CVE-2020-1');
INSERT INTO cve_score (cve, epss, kev) VALUES ('CVE-2020-1', 0.5, true);
INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk) VALUES
  ('ta','c1','GHSA-1','HIGH'), ('ta','c2','MAL-1','CRITICAL');
INSERT INTO scan_packages (tenant_id, scan_id, component_id, manifest_path, vulnerable) VALUES ('ta','s1','c1','package-lock.json',true);
INSERT INTO policy_violations (id, tenant_id, scan_id, project_version_id, component_id, rule_name, category, summary) VALUES
  ('pv1','ta','s1','va','c1','critical-or-high-vulnerability','vulnerability','Critical or high');
INSERT INTO package_analyses (id, tenant_id, component_id, project_version_id, scan_id, status, source) VALUES
  ('an1','ta','c2','va','s1','suspicious','guarddog');
INSERT INTO gh_installations (id, account_login, account_type, account_id, tenant_id, status) VALUES
  (1,'acme','Organization',100,'ta','linked'), (2,'other','Organization',200,NULL,'pending');
INSERT INTO gh_repositories (id, installation_id, full_name, default_branch) VALUES (10,1,'acme/web','main'), (20,2,'other/x','main');
INSERT INTO webhook_deliveries (delivery_id, event, status) VALUES ('d1','pull_request','failed');`)
	if err != nil {
		return err
	}
	_, err = tdb.Owner.Exec(ctx, riskSeed)
	return err
}

func token(tid, role string, sa bool) string {
	c := jwt.MapClaims{"tid": tid, "uid": "u-" + role, "role": role, "sa": sa, "exp": time.Now().Add(30 * time.Second).Unix()}
	s, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret)
	return s
}

type resp struct {
	code   int
	body   map[string]any
	raw    string
	header http.Header
}

func do(t *testing.T, method, path, bearer string, body any) resp {
	t.Helper()
	var rd io.Reader
	ct := "application/json"
	switch b := body.(type) {
	case nil:
	case *multipartBody:
		rd, ct = b.buf, b.ct
	case string:
		rd, ct = strings.NewReader(b), "application/x-ndjson"
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, srv.URL+path, rd)
	req.Header.Set("Content-Type", ct)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{code: res.StatusCode, raw: string(raw), header: res.Header}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

func expect(t *testing.T, r resp, code int) resp {
	t.Helper()
	if r.code != code {
		t.Fatalf("status %d, want %d: %s", r.code, code, r.raw)
	}
	return r
}

func items(r resp) []map[string]any {
	var out []map[string]any
	for _, it := range r.body["items"].([]any) {
		out = append(out, it.(map[string]any))
	}
	return out
}

func TestReadEndpoints(t *testing.T) {
	a := token("ta", "member", false)
	r := expect(t, do(t, "GET", "/api/v1/projects", a, nil), 200)
	p := items(r)
	if r.body["total"].(float64) != 1 || p[0]["name"] != "acme/web" || p[0]["vulns"].(float64) != 1 ||
		p[0]["violations"].(float64) != 1 || p[0]["components"].(float64) != 2 || p[0]["versions"].(float64) != 1 {
		t.Fatalf("projects: %s", r.raw)
	}
	if r := expect(t, do(t, "GET", "/api/v1/projects?has_violations=false", a, nil), 200); r.body["total"].(float64) != 0 {
		t.Fatalf("has_violations filter: %s", r.raw)
	}
	if r := expect(t, do(t, "GET", "/api/v1/projects?name=ACME&from=2000-01-01", a, nil), 200); r.body["total"].(float64) != 1 {
		t.Fatalf("name filter: %s", r.raw)
	}
	expect(t, do(t, "GET", "/api/v1/projects?page_size=13", a, nil), 400)

	d := expect(t, do(t, "GET", "/api/v1/dashboard?range=7d", a, nil), 200).body
	if d["malicious"].(float64) != 1 || d["suspicious"].(float64) != 1 || d["vulnerabilities"].(float64) != 1 ||
		d["violations"].(float64) != 1 || d["components"].(float64) != 2 || len(d["violations_over_time"].([]any)) != 7 ||
		len(d["top_projects"].([]any)) != 1 || len(d["violations_by_check"].([]any)) != 1 {
		t.Fatalf("dashboard: %v", d)
	}
	expect(t, do(t, "GET", "/api/v1/dashboard?range=1y", a, nil), 400)

	pd := expect(t, do(t, "GET", "/api/v1/projects/pa", a, nil), 200).body
	if len(pd["versions"].([]any)) != 1 {
		t.Fatalf("project detail: %v", pd)
	}
	sum := expect(t, do(t, "GET", "/api/v1/projects/pa/versions/va/summary", a, nil), 200).body
	if sum["components"].(float64) != 2 || sum["vulns"].(float64) != 1 || sum["violations"].(float64) != 1 {
		t.Fatalf("summary: %v", sum)
	}
	expect(t, do(t, "GET", "/api/v1/projects/pb/versions/va/summary", a, nil), 404)
	checks := map[string]float64{
		"/api/v1/projects/pa/versions/va/components":                2,
		"/api/v1/projects/pa/versions/va/components?has_vulns=true": 1,
		"/api/v1/projects/pa/versions/va/vulnerabilities":           1,
		"/api/v1/projects/pa/versions/va/violations":                1,
		"/api/v1/projects/pa/versions/va/scans":                     1,
		"/api/v1/projects/pa/versions/vb/scans":                     0,
		"/api/v1/components":                                        2,
		"/api/v1/components?ecosystem=npm&name=lod":                 1,
		"/api/v1/scans": 1,
		"/api/v1/scans?project_id=pa&status=success&has_vulns=true": 1,
		"/api/v1/package-analyses?status=suspicious&verified=false": 1,
		"/api/v1/vulnerabilities":                                   1,
		"/api/v1/vulnerabilities?risk=CRITICAL":                     0,
		"/api/v1/vulnerabilities/GHSA-1/components":                 1,
		"/api/v1/policy/violations?category=vulnerability":          1,
		"/api/v1/repositories":                                      1,
		"/api/v1/exclusions":                                        0,
		"/api/v1/endpoints":                                         0,
		"/api/v1/queries":                                           0,
	}
	for path, want := range checks {
		r := do(t, "GET", path, a, nil)
		if r.code != 200 || r.body["total"].(float64) != want {
			t.Errorf("%s: %d total=%v want %v: %s", path, r.code, r.body["total"], want, r.raw)
		}
	}
	vc := items(expect(t, do(t, "GET", "/api/v1/projects/pa/versions/va/components?has_vulns=true", a, nil), 200))
	if vc[0]["name"] != "lodash" || vc[0]["violations"].(float64) != 1 {
		t.Fatalf("version components: %v", vc)
	}
	if _, hidden := vc[0]["pv_id"]; hidden {
		t.Fatal("helper column leaked")
	}
	sc := expect(t, do(t, "GET", "/api/v1/scans/s1", a, nil), 200).body
	pk := sc["packages"].([]any)[0].(map[string]any)
	if len(pk["vulns"].([]any)) != 1 || len(pk["violations"].([]any)) != 1 || sc["report_md"] != "# report" {
		t.Fatalf("scan detail: %v", sc)
	}
	v := expect(t, do(t, "GET", "/api/v1/vulnerabilities/GHSA-1", a, nil), 200).body
	if v["kev"] != true || v["epss"].(float64) != 0.5 || len(v["aliases"].([]any)) != 1 || len(v["references"].([]any)) != 1 {
		t.Fatalf("vuln detail: %v", v)
	}
	an := expect(t, do(t, "GET", "/api/v1/package-analyses/an1", a, nil), 200).body
	if an["source"] != "guarddog" || an["component"].(map[string]any)["name"] != "evil" {
		t.Fatalf("analysis: %v", an)
	}
	in := expect(t, do(t, "GET", "/api/v1/integrations", a, nil), 200).body["github"].(map[string]any)
	if in["install_url"] == "" || len(in["installations"].([]any)) != 1 {
		t.Fatalf("integrations: %v", in)
	}
	st := expect(t, do(t, "GET", "/api/v1/settings", a, nil), 200).body
	if st["domain"] != "a.test" || st["block_mode"] != true {
		t.Fatalf("settings: %v", st)
	}
	qs := expect(t, do(t, "GET", "/api/v1/query/schema", a, nil), 200).body
	if len(qs["tables"].([]any)) < 14 {
		t.Fatalf("schema: %v", qs)
	}
}

func TestTenantIsolation(t *testing.T) {
	b := token("tb", "owner", false)
	r := expect(t, do(t, "GET", "/api/v1/projects", b, nil), 200)
	if r.body["total"].(float64) != 1 || items(r)[0]["name"] != "beta" {
		t.Fatalf("tenant b projects: %s", r.raw)
	}
	for _, p := range []string{"/api/v1/projects/pa", "/api/v1/scans/s1", "/api/v1/package-analyses/an1"} {
		expect(t, do(t, "GET", p, b, nil), 404)
	}
	for _, p := range []string{"/api/v1/components", "/api/v1/vulnerabilities", "/api/v1/repositories", "/api/v1/policy/violations"} {
		if r := expect(t, do(t, "GET", p, b, nil), 200); r.body["total"].(float64) != 0 {
			t.Errorf("%s leaks: %s", p, r.raw)
		}
	}
	d := expect(t, do(t, "GET", "/api/v1/dashboard", b, nil), 200).body
	if d["components"].(float64) != 0 || d["projects"].(float64) != 1 {
		t.Fatalf("dashboard leaks: %v", d)
	}
	expect(t, do(t, "POST", "/api/v1/package-analyses/an1/verify", b, map[string]string{"status": "clean"}), 404)
	expect(t, do(t, "POST", "/api/v1/scans", b, map[string]any{"repo_id": 10}), 404)
	q := expect(t, do(t, "POST", "/api/v1/query", b, map[string]string{"sql": "select name from q_projects"}), 200).body
	if len(q["rows"].([]any)) != 1 {
		t.Fatalf("query leaks: %v", q)
	}
	// No/invalid auth.
	expect(t, do(t, "GET", "/api/v1/projects", "", nil), 401)
	expect(t, do(t, "GET", "/api/v1/projects", "dg_notajwt", nil), 401)
}

func TestWritesAndRBAC(t *testing.T) {
	member, admin := token("ta", "member", false), token("ta", "admin", false)
	for _, c := range []struct{ method, path string }{
		{"PUT", "/api/v1/settings"}, {"POST", "/api/v1/api-keys"}, {"POST", "/api/v1/exclusions"},
		{"PUT", "/api/v1/policy"}, {"POST", "/api/v1/scans"}, {"POST", "/api/v1/package-analyses/an1/verify"},
	} {
		expect(t, do(t, c.method, c.path, member, map[string]any{}), 403)
	}
	expect(t, do(t, "GET", "/api/v1/admin/tenants", admin, nil), 403)

	// Settings.
	st := expect(t, do(t, "PUT", "/api/v1/settings", admin, map[string]any{"block_mode": false}), 200).body
	if st["block_mode"] != false || st["scan_draft_prs"] != false {
		t.Fatalf("settings put: %v", st)
	}
	// API keys.
	k := expect(t, do(t, "POST", "/api/v1/api-keys", admin, map[string]any{"name": "ci"}), 201).body
	if !strings.HasPrefix(k["key"].(string), "dg_") {
		t.Fatalf("key: %v", k)
	}
	keys := expect(t, do(t, "GET", "/api/v1/api-keys", member, nil), 200)
	if keys.body["total"].(float64) != 1 || strings.Contains(keys.raw, k["key"].(string)) {
		t.Fatalf("key list: %s", keys.raw)
	}
	expect(t, do(t, "DELETE", "/api/v1/api-keys/"+k["id"].(string), admin, nil), 204)
	expect(t, do(t, "DELETE", "/api/v1/api-keys/"+k["id"].(string), admin, nil), 404)
	// Exclusions.
	ex := expect(t, do(t, "POST", "/api/v1/exclusions", admin, map[string]any{"ecosystem": "npm", "name": "lodash", "reason": "accepted"}), 201).body
	if ex["status"] != "active" || ex["version"] != "*" {
		t.Fatalf("exclusion: %v", ex)
	}
	past := time.Now().Add(-time.Hour)
	ex = expect(t, do(t, "PUT", "/api/v1/exclusions/"+ex["id"].(string), admin, map[string]any{"ecosystem": "npm", "name": "lodash", "reason": "x", "expires_at": past}), 200).body
	if ex["status"] != "expired" {
		t.Fatalf("exclusion update: %v", ex)
	}
	if r := expect(t, do(t, "GET", "/api/v1/exclusions?status=expired", member, nil), 200); r.body["total"].(float64) != 1 {
		t.Fatalf("exclusion filter: %s", r.raw)
	}
	expect(t, do(t, "POST", "/api/v1/exclusions", admin, map[string]any{"ecosystem": "npm"}), 400)
	expect(t, do(t, "DELETE", "/api/v1/exclusions/"+ex["id"].(string), admin, nil), 204)
	// Policy.
	pol := expect(t, do(t, "GET", "/api/v1/policy", member, nil), 200).body
	if pol["presets"].(map[string]any)["vulnerability"].(map[string]any)["min_risk"] != "HIGH" {
		t.Fatalf("default policy: %v", pol)
	}
	bad := map[string]any{"presets": pol["presets"], "custom": []any{map[string]any{"name": "x", "category": "license", "expr": "licenses.exists("}}}
	expect(t, do(t, "PUT", "/api/v1/policy", admin, bad), 400)
	good := map[string]any{"presets": pol["presets"], "custom": []any{map[string]any{"name": "no-mit", "category": "license", "summary": "s", "expr": `licenses.exists(l, l == "MIT")`}}}
	if p := expect(t, do(t, "PUT", "/api/v1/policy", admin, good), 200).body; len(p["custom"].([]any)) != 1 {
		t.Fatalf("policy put: %v", p)
	}
	if p := expect(t, do(t, "GET", "/api/v1/policy", member, nil), 200).body; len(p["custom"].([]any)) != 1 {
		t.Fatalf("policy persisted: %v", p)
	}
	for _, c := range []struct {
		expr, name, version string
		matched             bool
	}{
		{`vulns.high.exists(v, v.id == "GHSA-1")`, "lodash", "4.17.0", true},
		{`licenses.exists(l, l == "MIT")`, "lodash", "4.17.0", true},
		{`vulns.all.exists(v, v.id.startsWith("MAL-"))`, "evil", "1.0.0", true},
		{`vulns.all.size() > 0`, "unknown", "1.0.0", false},
	} {
		r := expect(t, do(t, "POST", "/api/v1/policy/test", member, map[string]any{"expr": c.expr, "ecosystem": "npm", "name": c.name, "version": c.version}), 200).body
		if r["matched"] != c.matched || r["error"] != nil {
			t.Errorf("policy test %s on %s: %v", c.expr, c.name, r)
		}
	}
	if r := expect(t, do(t, "POST", "/api/v1/policy/test", member, map[string]any{"expr": "((", "ecosystem": "npm", "name": "x"}), 200).body; r["error"] == nil {
		t.Errorf("bad expr not reported: %v", r)
	}
	// Verify analysis.
	an := expect(t, do(t, "POST", "/api/v1/package-analyses/an1/verify", admin, map[string]string{"status": "malicious"}), 200).body
	if an["status"] != "malicious" || an["verified"] != true || an["source"] != "admin" || an["verified_by"] != "u-admin" {
		t.Fatalf("verify: %v", an)
	}
	expect(t, do(t, "POST", "/api/v1/package-analyses/an1/verify", admin, map[string]string{"status": "bogus"}), 400)
	// Saved queries + query errors.
	expect(t, do(t, "POST", "/api/v1/queries", member, map[string]string{"name": "q", "sql": "delete from x"}), 400)
	sq := expect(t, do(t, "POST", "/api/v1/queries", member, map[string]string{"name": "q", "sql": "select 1"}), 201).body
	expect(t, do(t, "DELETE", "/api/v1/queries/"+sq["id"].(string), member, nil), 204)
	expect(t, do(t, "POST", "/api/v1/query", member, map[string]string{"sql": "select * from nope"}), 400)
	// Manual scan enqueues a job.
	s := expect(t, do(t, "POST", "/api/v1/scans", admin, map[string]any{"repo_id": 10}), 202).body
	var kind, args string
	if err := tdb.Owner.QueryRow(context.Background(), `SELECT kind, args::text FROM river_job ORDER BY id DESC LIMIT 1`).Scan(&kind, &args); err != nil {
		t.Fatal(err)
	}
	if kind != "scan_repository" || !strings.Contains(args, s["scan_id"].(string)) || !strings.Contains(args, `"ref": "main"`) {
		t.Fatalf("job: %s %s", kind, args)
	}
	expect(t, do(t, "POST", "/api/v1/scans", admin, map[string]any{"repo_id": 20}), 404) // pending install
}

func TestAdmin(t *testing.T) {
	sa := token("", "", true)
	expect(t, do(t, "POST", "/api/v1/admin/tenants", sa, map[string]string{"tenant_id": "tc", "domain": "C.test"}), 201)
	expect(t, do(t, "POST", "/api/v1/admin/tenants", sa, map[string]string{"tenant_id": "td", "domain": "c.test"}), 409)
	expect(t, do(t, "POST", "/api/v1/admin/tenants", sa, map[string]string{"tenant_id": "td", "domain": "bad domain"}), 400)
	ts := expect(t, do(t, "GET", "/api/v1/admin/tenants", sa, nil), 200)
	if ts.body["total"].(float64) < 3 {
		t.Fatalf("tenants: %s", ts.raw)
	}
	for _, it := range items(ts) {
		if it["tenant_id"] == "ta" && (it["projects"].(float64) != 1 || it["installations"].(float64) != 1) {
			t.Fatalf("tenant counts: %v", it)
		}
	}
	tc := expect(t, do(t, "PATCH", "/api/v1/admin/tenants/tc", sa, map[string]bool{"disabled": true}), 200).body
	if tc["disabled_at"] == nil {
		t.Fatalf("disable: %v", tc)
	}
	// Disabled tenant: service JWTs are refused; a super-admin may still read for support.
	expect(t, do(t, "GET", "/api/v1/settings", token("tc", "owner", false), nil), 403)
	expect(t, do(t, "PUT", "/api/v1/settings", token("tc", "owner", true), map[string]bool{"block_mode": false}), 403)
	expect(t, do(t, "GET", "/api/v1/settings", token("tc", "owner", true), nil), 200)
	expect(t, do(t, "PATCH", "/api/v1/admin/tenants/tc", sa, map[string]bool{"disabled": false}), 200)
	expect(t, do(t, "GET", "/api/v1/settings", token("tc", "owner", false), nil), 200)
	expect(t, do(t, "PATCH", "/api/v1/admin/tenants/nope", sa, map[string]bool{"disabled": true}), 404)
	if r := expect(t, do(t, "GET", "/api/v1/admin/installations?status=pending", sa, nil), 200); r.body["total"].(float64) != 1 {
		t.Fatalf("installations: %s", r.raw)
	}
	expect(t, do(t, "POST", "/api/v1/admin/installations/2/link", sa, map[string]string{"tenant_id": "nope"}), 404)
	expect(t, do(t, "POST", "/api/v1/admin/installations/2/link", sa, map[string]string{"tenant_id": "tb"}), 200)
	if r := expect(t, do(t, "GET", "/api/v1/repositories", token("tb", "member", false), nil), 200); r.body["total"].(float64) != 1 {
		t.Fatalf("linked repos: %s", r.raw)
	}
	expect(t, do(t, "POST", "/api/v1/admin/installations/2/unlink", sa, nil), 200)
	expect(t, do(t, "GET", "/api/v1/admin/feeds", sa, nil), 200)
	if r := expect(t, do(t, "GET", "/api/v1/admin/webhooks?status=failed", sa, nil), 200); r.body["total"].(float64) != 1 {
		t.Fatalf("webhooks: %s", r.raw)
	}
	expect(t, do(t, "POST", "/api/v1/admin/webhooks/d1/redeliver", sa, nil), 202)
	expect(t, do(t, "POST", "/api/v1/admin/webhooks/nope/redeliver", sa, nil), 404)
	tdb.Owner.Exec(context.Background(), `INSERT INTO river_job (kind, args, state, max_attempts, errors, finalized_at)
		VALUES ('scan_upload', '{}', 'discarded', 1, ARRAY['{"error":"boom","at":"2024-01-01T00:00:00Z","attempt":1}'::jsonb], now())`)
	if r := expect(t, do(t, "GET", "/api/v1/admin/jobs/failed", sa, nil), 200); r.body["total"].(float64) < 1 {
		t.Fatalf("failed jobs: %s", r.raw)
	}
	// Super-admin without tenant cannot use tenant routes.
	expect(t, do(t, "GET", "/api/v1/projects", sa, nil), 403)
}

type multipartBody struct {
	buf *bytes.Buffer
	ct  string
}

func lockfiles(fields map[string]string, files map[string][]byte) *multipartBody {
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	for name, content := range files {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="lockfile"; filename=%q`, name))
		w, _ := mw.CreatePart(h)
		w.Write(content)
	}
	mw.Close()
	return &multipartBody{buf, mw.FormDataContentType()}
}

func apiKey(t *testing.T, tid string) string {
	k, err := auth.CreateKey(context.Background(), tdb.App, tid, "u", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return k.Key
}

func TestUploadScan(t *testing.T) {
	key := apiKey(t, "ta")
	fields := map[string]string{"project": "cli-proj", "version": "dev", "source": "gitlab"}
	expect(t, do(t, "POST", "/v1/scans", "", lockfiles(fields, map[string][]byte{"a/package-lock.json": []byte("{}")})), 401)
	expect(t, do(t, "POST", "/v1/scans", token("ta", "owner", false), lockfiles(fields, map[string][]byte{"package-lock.json": []byte("{}")})), 401)
	for _, bad := range []string{"../etc/passwd", "/abs/go.sum", `a\b`, "a/../../b", ""} {
		expect(t, do(t, "POST", "/v1/scans", key, lockfiles(fields, map[string][]byte{bad: []byte("x")})), 400)
	}
	many := map[string][]byte{}
	for i := range 51 {
		many[fmt.Sprintf("d%d/go.sum", i)] = []byte("x")
	}
	expect(t, do(t, "POST", "/v1/scans", key, lockfiles(fields, many)), 413)
	expect(t, do(t, "POST", "/v1/scans", key, lockfiles(fields, map[string][]byte{"big/yarn.lock": bytes.Repeat([]byte("x"), 10<<20+1)})), 413)
	expect(t, do(t, "POST", "/v1/scans", key, lockfiles(map[string]string{"project": "p", "source": "svn"}, map[string][]byte{"go.sum": []byte("x")})), 400)
	expect(t, do(t, "POST", "/v1/scans", key, lockfiles(fields, nil)), 400)

	r := expect(t, do(t, "POST", "/v1/scans", key, lockfiles(fields, map[string][]byte{"web/package-lock.json": []byte("{}"), "go.sum": []byte("x")})), 202).body
	id := r["scan_id"].(string)
	if r["status"] != "queued" || r["url"] != "https://app.test/scans/"+id {
		t.Fatalf("upload: %v", r)
	}
	var n int
	var kind string
	tdb.Owner.QueryRow(context.Background(), `SELECT count(*) FROM scan_uploads WHERE scan_id = $1 AND path IN ('web/package-lock.json','go.sum')`, id).Scan(&n)
	tdb.Owner.QueryRow(context.Background(), `SELECT kind FROM river_job WHERE args->>'scan_id' = $1`, id).Scan(&kind)
	if n != 2 || kind != "scan_upload" {
		t.Fatalf("uploads=%d kind=%q", n, kind)
	}
	if p := expect(t, do(t, "GET", "/api/v1/projects?source=gitlab", token("ta", "member", false), nil), 200); p.body["total"].(float64) != 1 {
		t.Fatalf("project upsert: %s", p.raw)
	}

	// ?wait=true returns once a worker finishes the scan.
	ScanWaitTimeout = 10 * time.Second
	go func() {
		time.Sleep(1500 * time.Millisecond)
		tdb.Owner.Exec(context.Background(), `UPDATE scans SET status='success', conclusion='failure', report_md='bad' WHERE trigger='cli' AND status='queued'`)
	}()
	w := expect(t, do(t, "POST", "/v1/scans?wait=true", key, lockfiles(fields, map[string][]byte{"go.sum": []byte("x")})), 200).body
	if w["conclusion"] != "failure" || w["report_md"] != "bad" {
		t.Fatalf("wait: %v", w)
	}
	expect(t, do(t, "GET", "/v1/scans/"+w["scan_id"].(string), key, nil), 200)
	expect(t, do(t, "GET", "/v1/scans/"+w["scan_id"].(string), apiKey(t, "tb"), nil), 404)
}

func TestEndpointIngest(t *testing.T) {
	key := apiKey(t, "ta")
	expect(t, do(t, "POST", "/v1/endpoints/checkin", key, map[string]string{"endpoint_type": "laptop"}), 400)
	c := expect(t, do(t, "POST", "/v1/endpoints/checkin", key, map[string]string{"identifier": "host-1", "hostname": "h", "os": "linux"}), 200).body
	id := c["endpoint_id"].(string)
	again := expect(t, do(t, "POST", "/v1/endpoints/checkin", key, map[string]string{"identifier": "host-1"}), 200).body
	if again["endpoint_id"] != id {
		t.Fatal("checkin not idempotent")
	}
	inv := map[string]any{"items": []map[string]any{
		{"kind": "coding_agent", "name": "claude-code", "config_path": "~/.claude"},
		{"kind": "mcp_server", "name": "github", "config_path": "~/.claude.json", "details": map[string]any{"command": "npx"}},
	}}
	expect(t, do(t, "POST", "/v1/endpoints/"+id+"/inventory", key, inv), 200)
	inv["items"] = inv["items"].([]map[string]any)[1:]
	expect(t, do(t, "POST", "/v1/endpoints/"+id+"/inventory", key, inv), 200)
	expect(t, do(t, "POST", "/v1/endpoints/"+id+"/inventory", key, map[string]any{"items": []map[string]any{{"kind": "bogus", "name": "x"}}}), 400)

	pmg := `{"timestamp":"2025-01-02T03:04:05Z","event_type":"malware_blocked","message":"blocked","package_name":"evil","version":"1.0.0","ecosystem":"npm","details":{"reason":"MAL-1"}}
{"timestamp":"2025-01-02T03:04:06Z","event_type":"install_allowed","message":"ok","package_name":"lodash"}
`
	if r := expect(t, do(t, "POST", "/v1/endpoints/"+id+"/pmg-events", key, pmg), 200).body; r["inserted"].(float64) != 2 {
		t.Fatalf("pmg: %v", r)
	}
	expect(t, do(t, "POST", "/v1/endpoints/"+id+"/pmg-events", key, "{not json}\n"), 400)

	ev := []map[string]any{{"$schema": "https://raw.githubusercontent.com/safedep/gryph/main/schema/event.schema.json",
		"id": "0b8f0f1e-0000-4000-8000-000000000001", "session_id": "0b8f0f1e-0000-4000-8000-0000000000aa", "sequence": 1,
		"timestamp": "2025-01-02T03:04:05Z", "agent_name": "claude-code", "action_type": "command_exec", "result_status": "success",
		"tool_name": "Bash", "is_sensitive": false, "payload": map[string]any{"command": "ls"}}}
	if r := expect(t, do(t, "POST", "/v1/endpoints/"+id+"/agent-events", key, ev), 200).body; r["inserted"].(float64) != 1 {
		t.Fatalf("agent events: %v", r)
	}
	if r := expect(t, do(t, "POST", "/v1/endpoints/"+id+"/agent-events", key, ev), 200).body; r["inserted"].(float64) != 0 || r["duplicates"].(float64) != 1 {
		t.Fatalf("dedupe: %v", r)
	}
	expect(t, do(t, "POST", "/v1/endpoints/"+id+"/agent-events", key, []map[string]any{{"id": "x"}}), 400)
	// Other tenant cannot write to this endpoint.
	expect(t, do(t, "POST", "/v1/endpoints/"+id+"/pmg-events", apiKey(t, "tb"), pmg), 404)

	m := token("ta", "member", false)
	eps := items(expect(t, do(t, "GET", "/api/v1/endpoints", m, nil), 200))
	if len(eps) != 1 || eps[0]["inventory_count"].(float64) != 1 || eps[0]["last_sync_at"] == nil {
		t.Fatalf("endpoints: %v", eps)
	}
	expect(t, do(t, "GET", "/api/v1/endpoints/"+id, m, nil), 200)
	inv2 := items(expect(t, do(t, "GET", "/api/v1/endpoints/"+id+"/inventory", m, nil), 200))
	if len(inv2) != 1 || inv2[0]["name"] != "github" {
		t.Fatalf("inventory replace: %v", inv2)
	}
	if r := expect(t, do(t, "GET", "/api/v1/endpoints/"+id+"/package-events?event_type=malware_blocked", m, nil), 200); r.body["total"].(float64) != 1 {
		t.Fatalf("package events: %s", r.raw)
	}
	if r := expect(t, do(t, "GET", "/api/v1/endpoints/"+id+"/agent-events", m, nil), 200); r.body["total"].(float64) != 1 {
		t.Fatalf("agent events list: %s", r.raw)
	}
	if r := expect(t, do(t, "GET", "/api/v1/endpoints", token("tb", "member", false), nil), 200); r.body["total"].(float64) != 0 {
		t.Fatalf("endpoint leak: %s", r.raw)
	}
}
