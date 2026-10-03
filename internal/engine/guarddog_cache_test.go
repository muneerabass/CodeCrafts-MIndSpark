package engine

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/depguard/depguard/internal/engine/testpg"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/riverqueue/river"
)

// TestGuarddogVerdictCache: a package version is analysed once across
// tenants; each tenant still gets its analysis and an unusual-behaviour
// violation whose blocking flag follows its own policy.
func TestGuarddogVerdictCache(t *testing.T) {
	ctx := context.Background()
	pg := testpg.Start(t)
	_, err := pg.Owner.Exec(ctx, `
		INSERT INTO tenant_settings (tenant_id, domain, policy) VALUES
		  ('t1', 't1.example', '{}'),
		  ('t2', 't2.example', '{"presets":{"suspicious":{"blocking":[]}}}'),
		  ('t3', 't3.example', '{"presets":{"suspicious":{"unusual_behaviour":false}}}');
		INSERT INTO projects (id, tenant_id, source, name) SELECT 'p'||t, 't'||t, 'cli', 'app' FROM generate_series(1,3) t;
		INSERT INTO project_versions (id, tenant_id, project_id, name) SELECT 'v'||t, 't'||t, 'p'||t, 'main' FROM generate_series(1,3) t;
		INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger) SELECT 's'||t, 't'||t, 'p'||t, 'v'||t, 'cli' FROM generate_series(1,3) t;
		INSERT INTO components (id, tenant_id, ecosystem, name, version, purl)
		  SELECT 'c'||t, 't'||t, 'npm', 'shady', '1.0.0', 'pkg:npm/shady@1.0.0' FROM generate_series(1,3) t;`)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	gd := filepath.Join(dir, "guarddog")
	script := "#!/bin/sh\necho run >> " + runs + "\n" +
		`echo '{"issues":1,"errors":{},"risk_score":{"score":7.5,"label":"high"},"results":{"npm-install-script":"curl | sh","typosquatting":null,"shady-links":[]}}'` + "\n"
	if err := os.WriteFile(gd, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &guarddogWorker{d: Deps{Pool: pg.App, GuarddogBin: gd, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	for _, n := range []string{"1", "2", "3"} {
		job := &river.Job[jobs.GuarddogAnalyze]{Args: jobs.GuarddogAnalyze{TenantID: "t" + n, ComponentID: "c" + n, ScanID: "s" + n,
			Ecosystem: "npm", Name: "shady", Version: "1.0.0"}}
		if err := w.Work(ctx, job); err != nil {
			t.Fatalf("tenant %s: %v", n, err)
		}
	}

	if b, _ := os.ReadFile(runs); strings.Count(string(b), "run") != 1 {
		t.Fatalf("guarddog ran %d times, want 1", strings.Count(string(b), "run"))
	}
	var rules []string
	var issues int
	if err := pg.Owner.QueryRow(ctx, `SELECT issues, rules FROM guarddog_verdict WHERE ecosystem='npm' AND name='shady' AND version='1.0.0'`).
		Scan(&issues, &rules); err != nil || issues != 1 || !slices.Equal(rules, []string{"npm-install-script"}) {
		t.Fatalf("verdict: %d %v %v", issues, rules, err)
	}
	for _, n := range []string{"1", "2", "3"} {
		var status string
		var suspicious int
		if err := pg.Owner.QueryRow(ctx, `SELECT pa.status, s.suspicious_count FROM package_analyses pa JOIN scans s ON s.id = pa.scan_id
			WHERE pa.tenant_id=$1 AND pa.source='guarddog'`, "t"+n).Scan(&status, &suspicious); err != nil || status != "suspicious" || suspicious != 1 {
			t.Fatalf("tenant %s analysis: %s %d %v", n, status, suspicious, err)
		}
	}

	type violation struct {
		blocking         bool
		summary, details string
	}
	got := map[string]violation{}
	rows, err := pg.Owner.Query(ctx, `SELECT tenant_id, blocking, summary, details::text FROM policy_violations
		WHERE rule_name='unusual-behaviour' AND category='suspicious' AND severity='high' AND project_version_id='v'||substr(tenant_id,2)`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var tenant string
		var v violation
		if err := rows.Scan(&tenant, &v.blocking, &v.summary, &v.details); err != nil {
			t.Fatal(err)
		}
		got[tenant] = v
	}
	if len(got) != 2 || !got["t1"].blocking || got["t2"].blocking {
		t.Fatalf("violations = %+v", got)
	}
	var d map[string]any
	json.Unmarshal([]byte(got["t1"].details), &d)
	if got["t1"].summary != "Suspicious behaviour detected by heuristics: npm-install-script" || d["risk_score"] != 7.5 ||
		len(d["rules"].([]any)) != 1 {
		t.Fatalf("t1 violation = %+v", got["t1"])
	}

	// A repeat job for an analysed component is a no-op.
	if err := w.Work(ctx, &river.Job[jobs.GuarddogAnalyze]{Args: jobs.GuarddogAnalyze{TenantID: "t1", ComponentID: "c1", ScanID: "s1",
		Ecosystem: "npm", Name: "shady", Version: "1.0.0"}}); err != nil {
		t.Fatal(err)
	}
	var n int
	pg.Owner.QueryRow(ctx, `SELECT count(*) FROM policy_violations WHERE tenant_id='t1'`).Scan(&n)
	if n != 1 {
		t.Fatalf("t1 violations after repeat = %d", n)
	}
}
