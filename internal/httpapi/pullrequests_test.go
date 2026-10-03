package httpapi

import (
	"context"
	"strings"
	"testing"
)

func TestPullRequests(t *testing.T) {
	ctx := context.Background()
	_, err := tdb.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain) VALUES ('tpr','pr.test'), ('tpr2','pr2.test');
INSERT INTO projects (id, tenant_id, source, name, url, gh_repo_id) VALUES ('ppr','tpr','github','acme/shop','https://github.com/acme/shop', 501),
  ('ppr2','tpr2','github','other/app','', 502);
INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('vpr','tpr','ppr','main');
INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status, pr_number, head_sha, conclusion, vulns_count, malicious_count, pr_summary)
  VALUES ('spr1','tpr','ppr','vpr','pull_request','success',12,'h12','failure',3,1,
    '{"scan_id":"spr1","checks":{"malware":"fail"},"fixes":[{"kind":"malware","severity":"critical","blocking":true,"title":"Remove malicious package"}]}'),
         ('spr2','tpr','ppr','vpr','pull_request','success',13,'h13','success',0,0,'{"scan_id":"spr2","checks":{}}');
INSERT INTO pull_requests (id, tenant_id, repo_id, repo_full_name, number, title, author_login, state, head_sha, latest_scan_id, urgency, urgency_level, reasons, labels, gh_updated_at, installation_id)
  VALUES ('pr12','tpr',501,'acme/shop',12,'Add payments SDK','mallory','open','h12','spr1',100,'critical','[{"kind":"malware","text":"Adds malicious package"}]','{malware,blocked}', now() - interval '2 days', 1),
         ('pr13','tpr',501,'acme/shop',13,'Fix typo','ada','open','h13','spr2',0,'clean','[]','{docs}', now(), 1),
         ('pr14','tpr',501,'acme/shop',14,'Old feature','ada','merged','h14',NULL,70,'high','[]','{}', now() - interval '9 days', 1),
         ('pr21','tpr2',502,'other/app',21,'Other tenant','eve','open','h21',NULL,90,'critical','[]','{}', now(), 2);
INSERT INTO pr_reviews (id, tenant_id, pr_id, scan_id, head_sha, findings, labels, ai_status, ai_model, ai_summary)
  VALUES ('rv12','tpr','pr12','spr1','h12','[{"source":"ai","file":"api/pay.js","line":4,"severity":"high","title":"SSRF"}]','{feature}','done','qwen','Adds a payment call.');`)
	if err != nil {
		t.Fatal(err)
	}
	member, owner := token("tpr", "member", false), token("tpr", "owner", false)

	// Inbox: open PRs only by default, most urgent first, no other tenant's PRs.
	l := expect(t, do(t, "GET", "/api/v1/pull-requests", member, nil), 200).body
	items := listOf(l["items"])
	if l["total"].(float64) != 2 || mapOf(items[0])["number"].(float64) != 12 || mapOf(items[1])["number"].(float64) != 13 {
		t.Fatalf("inbox: %v", l)
	}
	first := mapOf(items[0])
	if mapOf(first["project"])["id"] != "ppr" || mapOf(first["scan"])["malicious"].(float64) != 1 || mapOf(first["review"])["findings"].(float64) != 1 ||
		first["urgency_level"] != "critical" || len(listOf(first["reasons"])) != 1 {
		t.Fatalf("first item: %v", first)
	}
	if _, ok := first["state_rank"]; ok {
		t.Fatal("internal sort column leaked")
	}
	for path, want := range map[string]float64{
		"/api/v1/pull-requests?state=all": 3, "/api/v1/pull-requests?state=merged": 1, "/api/v1/pull-requests?level=clean": 1,
		"/api/v1/pull-requests?q=payments": 1, "/api/v1/pull-requests?author=ada&state=all": 2, "/api/v1/pull-requests?label=docs": 1,
		"/api/v1/projects/ppr/pull-requests?state=all": 3, "/api/v1/projects/ppr2/pull-requests": 0,
	} {
		if got := expect(t, do(t, "GET", path, member, nil), 200).body["total"].(float64); got != want {
			t.Errorf("%s: total %v, want %v", path, got, want)
		}
	}
	expect(t, do(t, "GET", "/api/v1/pull-requests?state=bogus", member, nil), 400)

	sum := expect(t, do(t, "GET", "/api/v1/pull-requests/summary", member, nil), 200).body
	if sum["open"].(float64) != 2 || mapOf(sum["by_level"])["critical"].(float64) != 1 || sum["merged_with_issues"].(float64) != 1 {
		t.Fatalf("summary %v", sum)
	}

	// Detail.
	d := expect(t, do(t, "GET", "/api/v1/projects/ppr/pull-requests/12", member, nil), 200).body
	if d["title"] != "Add payments SDK" || mapOf(d["review"])["ai_status"] != "done" || len(listOf(mapOf(d["summary"])["fixes"])) != 1 ||
		len(listOf(d["history"])) != 1 {
		t.Fatalf("detail %v", d)
	}
	expect(t, do(t, "GET", "/api/v1/projects/ppr/pull-requests/99", member, nil), 404)
	expect(t, do(t, "GET", "/api/v1/projects/ppr2/pull-requests/21", member, nil), 404) // other tenant

	// Actions: members can't, admins/owners queue a job; closed PRs and empty comments are refused.
	expect(t, do(t, "POST", "/api/v1/projects/ppr/pull-requests/12/comment", member, map[string]string{"body": "hi"}), 403)
	a := expect(t, do(t, "POST", "/api/v1/projects/ppr/pull-requests/12/comment", owner, map[string]string{"body": "Please upgrade lodash."}), 202).body
	if a["status"] != "queued" || a["activity_id"] == "" {
		t.Fatalf("action %v", a)
	}
	expect(t, do(t, "POST", "/api/v1/projects/ppr/pull-requests/12/comment", owner, map[string]string{"body": "  "}), 400)
	expect(t, do(t, "POST", "/api/v1/projects/ppr/pull-requests/12/rescan", owner, nil), 202)
	expect(t, do(t, "POST", "/api/v1/projects/ppr/pull-requests/12/review", owner, map[string]string{"body": "Blocked: malware"}), 202)
	expect(t, do(t, "POST", "/api/v1/projects/ppr/pull-requests/12/ai-review", owner, nil), 202)
	expect(t, do(t, "POST", "/api/v1/projects/ppr/pull-requests/14/rescan", owner, nil), 400) // merged
	expect(t, do(t, "POST", "/api/v1/projects/ppr/pull-requests/12/explode", owner, nil), 404)
	var queued, activity int
	tdb.Owner.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind='pr_action' AND args->>'tenant_id'='tpr'`).Scan(&queued)
	tdb.Owner.QueryRow(ctx, `SELECT count(*) FROM pr_activity WHERE pr_id='pr12'`).Scan(&activity)
	if queued != 4 || activity != 4 {
		t.Fatalf("queued %d activity %d", queued, activity)
	}
	d = expect(t, do(t, "GET", "/api/v1/projects/ppr/pull-requests/12", member, nil), 200).body
	if acts := listOf(d["activity"]); len(acts) != 4 || !strings.Contains(mapOf(acts[3])["body"].(string), "lodash") {
		t.Fatalf("activity %v", d["activity"])
	}

	// Settings: defaults, validation, round trip, members read-only.
	ps := expect(t, do(t, "GET", "/api/v1/settings/pr", member, nil), 200).body
	set := mapOf(ps["settings"])
	if set["comment_mode"] != "always" || mapOf(set["ai_review"])["enabled"] != true || mapOf(set["labels"])["prefix"] != "depguard:" {
		t.Fatalf("defaults %v", ps)
	}
	expect(t, do(t, "PUT", "/api/v1/settings/pr", member, map[string]any{"comment_mode": "never"}), 403)
	expect(t, do(t, "PUT", "/api/v1/settings/pr", owner, map[string]any{"comment_mode": "sometimes"}), 400)
	expect(t, do(t, "PUT", "/api/v1/settings/pr", owner, map[string]any{"comment_mode": "always", "header": strings.Repeat("x", 2001)}), 400)
	expect(t, do(t, "PUT", "/api/v1/settings/pr", owner, map[string]any{"comment_mode": "always", "sections": map[string]bool{"nope": true}}), 400)
	ps = expect(t, do(t, "PUT", "/api/v1/settings/pr", owner, map[string]any{"comment_mode": "issues", "header": "Security team: ping #appsec",
		"request_changes_on_block": true, "ai_review": map[string]any{"enabled": false, "max_diff_kb": 100}}), 200).body
	set = mapOf(ps["settings"])
	if set["comment_mode"] != "issues" || set["header"] != "Security team: ping #appsec" || mapOf(set["ai_review"])["enabled"] != false ||
		mapOf(set["labels"])["enabled"] != true {
		t.Fatalf("saved %v", ps)
	}
	if got := expect(t, do(t, "GET", "/api/v1/settings/pr", token("tpr2", "member", false), nil), 200).body; mapOf(got["settings"])["comment_mode"] != "always" {
		t.Fatalf("settings leaked across tenants: %v", got)
	}
}
