package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/depguard/depguard/internal/jobs"
)

// An upgrade reports only the guarddog rules the new version gained.
func TestGuarddogUpgradeDiff(t *testing.T) {
	ctx := context.Background()
	gd := filepath.Join(t.TempDir(), "guarddog")
	os.WriteFile(gd, []byte(`#!/bin/sh
case "$*" in
*"--version 2.0.0"*) echo '{"issues":2,"errors":{},"results":{"npm-install-script":"x","npm-exfiltrate-sensitive-data":"y"}}';;
*) echo '{"issues":1,"errors":{},"results":{"npm-install-script":"x"}}';;
esac
`), 0o755)
	h := newHarness(t, "", func(d *Deps) { d.GuarddogBin = gd })
	h.gh.blobs["baseblob"] = npmLock("up-pkg@1.0.0")
	h.gh.baseFiles["package-lock.json"] = "baseblob"
	h.gh.setPR(1, "h1", []map[string]string{{"filename": "package-lock.json", "status": "modified", "sha": "head1"}},
		map[string][]byte{"head1": npmLock("up-pkg@2.0.0")})
	if _, err := h.rc.Insert(ctx, jobs.ScanPullRequest{InstallationID: 10, RepoID: 7, RepoFullName: "o/r", PRNumber: 1,
		BaseSHA: "base", HeadSHA: "h1", BaseRef: "main", HeadRef: "feat"}, nil); err != nil {
		t.Fatal(err)
	}
	h.await(t, "scan_pull_request")
	h.await(t, "guarddog_analyze")
	var rule, summary string
	var blocking bool
	if err := h.pg.Owner.QueryRow(ctx, `SELECT rule_name, summary, blocking FROM policy_violations WHERE category='suspicious'`).Scan(&rule, &summary, &blocking); err != nil {
		t.Fatal(err)
	}
	if rule != "new-behaviour" || !blocking || summary != "up-pkg@2.0.0 adds behaviour 1.0.0 did not have: npm-exfiltrate-sensitive-data" {
		t.Fatalf("%s %v %q", rule, blocking, summary)
	}
	var cached int
	h.pg.Owner.QueryRow(ctx, `SELECT count(*) FROM guarddog_verdict WHERE name='up-pkg'`).Scan(&cached)
	if cached != 2 || strings.Contains(summary, "npm-install-script") {
		t.Fatalf("verdicts cached %d", cached)
	}
}
