package httpapi

import (
	"context"
	"testing"
)

func TestFixQueueAndSLA(t *testing.T) {
	ctx := context.Background()
	_, err := tdb.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain) VALUES ('tq','q.test');
INSERT INTO projects (id, tenant_id, source, name, url) VALUES ('pq1','tq','cli','api',''), ('pq2','tq','cli','web','');
INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('vq1','tq','pq1','main'), ('vq2','tq','pq2','main');
INSERT INTO components (id, tenant_id, ecosystem, name, version, purl) VALUES
  ('qa','tq','npm','lodash','4.17.15','pkg:npm/lodash@4.17.15'), ('qb','tq','npm','axios','1.0.0','pkg:npm/axios@1.0.0'),
  ('qc','tq','npm','gone','1.0.0','pkg:npm/gone@1.0.0');
INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path, direct) VALUES
  ('tq','vq1','qa','package-lock.json',true), ('tq','vq2','qa','package-lock.json',false), ('tq','vq1','qb','package-lock.json',true);
INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk, fixed_in, first_seen, seen_current, resolved_at) VALUES
  ('tq','qa','GHSA-q1','CRITICAL','4.17.19', now() - interval '10 days', true, NULL),
  ('tq','qa','GHSA-q2','HIGH','4.17.21', now() - interval '10 days', true, NULL),
  ('tq','qb','GHSA-q3','MEDIUM','1.6.0', now() - interval '1 day', true, NULL),
  ('tq','qc','GHSA-q4','CRITICAL','2.0.0', now() - interval '20 days', true, now() - interval '2 days');`)
	if err != nil {
		t.Fatal(err)
	}
	member, owner := token("tq", "member", false), token("tq", "owner", false)

	q := expect(t, do(t, "GET", "/api/v1/fix-queue", member, nil), 200).body
	items := listOf(q["items"])
	if q["total"].(float64) != 2 || len(items) != 2 {
		t.Fatalf("queue %v", q)
	}
	first := mapOf(items[0])
	// lodash: (10+5) points × 2 projects = 30 of 32 total; fix = highest fixed version; critical 7-day deadline passed.
	if first["name"] != "lodash" || first["fixed_in"] != "4.17.21" || first["weight"].(float64) != 30 || first["share"].(float64) != 93.8 ||
		first["overdue"] != true || len(listOf(first["projects"])) != 2 || first["command"] != "npm install lodash@4.17.21" {
		t.Fatalf("first %v", first)
	}
	if s := mapOf(q["summary"]); s["overdue"].(float64) != 1 || s["fixable"].(float64) != 2 {
		t.Fatalf("summary %v", s)
	}
	if expect(t, do(t, "GET", "/api/v1/fix-queue?project_id=pq2", member, nil), 200).body["total"].(float64) != 1 {
		t.Fatal("project filter")
	}

	// Vulnerability list: deadline columns and the overdue filter (GHSA-q1 critical/10d and GHSA-q2 high/30d → only q1 overdue).
	l := expect(t, do(t, "GET", "/api/v1/vulnerabilities?overdue=1", member, nil), 200).body
	if l["total"].(float64) != 1 || mapOf(listOf(l["items"])[0])["id"] != "GHSA-q1" {
		t.Fatalf("overdue vulns %v", l)
	}
	if _, ok := mapOf(listOf(l["items"])[0])["days"]; ok {
		t.Fatal("internal days column leaked")
	}

	d := expect(t, do(t, "GET", "/api/v1/dashboard", member, nil), 200).body
	if d["overdue"].(float64) != 1 || mapOf(d["fixed"])["resolved"].(float64) != 1 || mapOf(d["fixed"])["on_time"].(float64) != 0 {
		t.Fatalf("dashboard overdue=%v fixed=%v", d["overdue"], d["fixed"])
	}

	// Stretching the critical deadline makes lodash on time.
	expect(t, do(t, "PUT", "/api/v1/settings/sla", member, map[string]int{"critical": 30}), 403)
	expect(t, do(t, "PUT", "/api/v1/settings/sla", owner, map[string]int{"critical": 400}), 400)
	s := expect(t, do(t, "PUT", "/api/v1/settings/sla", owner, map[string]int{"critical": 30, "high": 60, "medium": 90, "low": 0}), 200).body
	if s["critical"].(float64) != 30 {
		t.Fatalf("sla %v", s)
	}
	if expect(t, do(t, "GET", "/api/v1/vulnerabilities?overdue=1", member, nil), 200).body["total"].(float64) != 0 {
		t.Fatal("still overdue after changing the deadline")
	}
	if d := expect(t, do(t, "GET", "/api/v1/dashboard", member, nil), 200).body; mapOf(d["fixed"])["on_time"].(float64) != 1 {
		t.Fatalf("fixed on time %v", d["fixed"])
	}
}
