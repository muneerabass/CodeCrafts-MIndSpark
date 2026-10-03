package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/engine/testpg"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/jackc/pgx/v5"
)

func TestFixPR(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, `{"issues":0,"errors":{},"results":{}}`, nil)
	h.gh.blobs["reqblob"] = []byte("flask==2.0.1\nrequests==2.25.0  # http\n")
	h.gh.baseFiles["api/requirements.txt"] = "reqblob"
	_, err := h.pg.Owner.Exec(ctx, `
		INSERT INTO gh_repositories (id, installation_id, full_name, default_branch) VALUES (7, 10, 'o/r', 'main');
		INSERT INTO projects (id, tenant_id, source, name, url, gh_repo_id) VALUES ('p1','t1','github','o/r','',7);
		INSERT INTO components (id, tenant_id, ecosystem, name, version, purl) VALUES ('c1','t1','PyPI','requests','2.25.0','pkg:pypi/requests@2.25.0');
		INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk, fixed_in) VALUES ('t1','c1','GHSA-j8r2-6x86-q33q','MEDIUM','2.31.0');
		INSERT INTO fix_prs (id, tenant_id, project_id, ecosystem, name, from_version, to_version, manifest_path)
		  VALUES ('f1','t1','p1','PyPI','requests','2.25.0','2.31.0','api/requirements.txt'),
		         ('f2','t1','p1','Cargo','serde','1.0.0','1.0.9','Cargo.lock');`)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"f1", "f2"} {
		if _, err := h.rc.Insert(ctx, jobs.CreateFixPR{TenantID: "t1", FixID: id}, nil); err != nil {
			t.Fatal(err)
		}
		h.await(t, "create_fix_pr")
	}
	var status, url, branch, msg string
	var num int
	if err := h.pg.Owner.QueryRow(ctx, `SELECT status, pr_url, COALESCE(pr_number,0), branch, error FROM fix_prs WHERE id='f1'`).Scan(&status, &url, &num, &branch, &msg); err != nil {
		t.Fatal(err)
	}
	if status != "open" || num != 77 || url != "https://github.com/o/r/pull/77" || branch != "depguard/fix-requests-2.31.0-api" {
		t.Fatalf("f1: %s %d %s %s %s", status, num, url, branch, msg)
	}
	h.gh.mu.Lock()
	tree, ref, pr := h.gh.fixTree, h.gh.fixRef, h.gh.fixPR
	h.gh.mu.Unlock()
	entry, _ := tree[0].(map[string]any)
	if len(tree) != 1 || entry["path"] != "api/requirements.txt" || entry["content"] != "flask==2.0.1\nrequests==2.31.0 # http\n" {
		t.Fatalf("tree %v", tree)
	}
	if ref != "refs/heads/depguard/fix-requests-2.31.0-api" || pr["base"] != "main" || !strings.Contains(pr["body"].(string), "GHSA-j8r2-6x86-q33q") {
		t.Fatalf("ref %s pr %v", ref, pr)
	}
	if err := h.pg.Owner.QueryRow(ctx, `SELECT status, error FROM fix_prs WHERE id='f2'`).Scan(&status, &msg); err != nil || status != "unsupported" || !strings.Contains(msg, "cargo update -p serde") {
		t.Fatalf("f2: %v %s %s", err, status, msg)
	}
}

func TestTrackResolved(t *testing.T) {
	ctx := context.Background()
	pg := testpg.Start(t)
	_, err := pg.Owner.Exec(ctx, `
		INSERT INTO tenant_settings (tenant_id, domain) VALUES ('t1','t1.example');
		INSERT INTO projects (id, tenant_id, source, name, url) VALUES ('p1','t1','cli','app','');
		INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('v1','t1','p1','main');
		INSERT INTO components (id, tenant_id, ecosystem, name, version, purl) VALUES
		  ('old','t1','npm','a','1','pkg:npm/a@1'), ('new','t1','npm','a','2','pkg:npm/a@2'), ('pr','t1','npm','b','1','pkg:npm/b@1');
		INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path) VALUES ('t1','v1','new','package-lock.json');
		INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk, seen_current) VALUES
		  ('t1','old','GHSA-1','HIGH',true), ('t1','new','GHSA-2','HIGH',false), ('t1','pr','GHSA-3','HIGH',false);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WithTenantTx(ctx, pg.App, "t1", func(tx pgx.Tx) error { return trackResolved(ctx, tx) }); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	rows, _ := pg.Owner.Query(ctx, `SELECT component_id, seen_current::text || '/' || (resolved_at IS NOT NULL)::text FROM component_vulnerabilities`)
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		got[k] = v
	}
	// old left the inventory → resolved; new is current; a PR-only package never counts as fixed.
	if got["old"] != "true/true" || got["new"] != "true/false" || got["pr"] != "false/false" {
		t.Fatalf("%v", got)
	}
}
