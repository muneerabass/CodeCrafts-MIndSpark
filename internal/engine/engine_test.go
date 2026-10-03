package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/engine/testpg"
	"github.com/depguard/depguard/internal/ghapp"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/render"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

// npmLock builds a minimal package-lock.json (v3) for "name@version" args.
func npmLock(pkgs ...string) []byte {
	deps := map[string]string{}
	packages := map[string]any{}
	for _, p := range pkgs {
		name, ver, _ := strings.Cut(p, "@")
		deps[name] = ver
		packages["node_modules/"+name] = map[string]any{"version": ver,
			"resolved": fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz", name, name, ver)}
	}
	packages[""] = map[string]any{"name": "app", "version": "1.0.0", "dependencies": deps}
	return mustJSON(map[string]any{"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": packages})
}

type fakeEnricher map[string][2]string // name -> {advisory id, risk}

func (f fakeEnricher) Enrich(_ context.Context, pkgs []*models.Package) error {
	for _, p := range pkgs {
		vs := []insightapi.PackageVulnerability{}
		if v, ok := f[p.GetName()]; ok {
			id, risk := v[0], insightapi.PackageVulnerabilitySeveritiesRisk(v[1])
			typ := insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3
			sev := []struct {
				Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
				Score *string                                        `json:"score,omitempty"`
				Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
			}{{Risk: &risk, Type: &typ}}
			vs = append(vs, insightapi.PackageVulnerability{Id: &id, Severities: &sev})
		}
		lic := []insightapi.License{"MIT"}
		p.Insights = &insightapi.PackageVersionInsight{Vulnerabilities: &vs, Licenses: &lic}
	}
	return nil
}

// fakeGitHub serves the subset of the REST API the engine uses.
type fakeGitHub struct {
	mu        sync.Mutex
	blobs     map[string][]byte // sha -> content
	baseFiles map[string]string // path -> blob sha at merge base
	prFiles   map[int][]map[string]string
	heads     map[int]string // pr -> current head sha
	checks    map[int64]map[string]any
	comments  map[int64]string // id -> body
	created   int              // comments created
	updated   int              // comments edited
	nextID    int64
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{blobs: map[string][]byte{}, baseFiles: map[string]string{}, prFiles: map[int][]map[string]string{},
		heads: map[int]string{}, checks: map[int64]map[string]any{}, comments: map[int64]string{}, nextID: 100}
}

func (g *fakeGitHub) handler() http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		write(w, map[string]any{"token": "inst-token", "expires_at": time.Now().Add(time.Hour)})
	})
	mux.HandleFunc("GET /repos/o/r/compare/{basehead}", func(w http.ResponseWriter, r *http.Request) {
		base, _, _ := strings.Cut(r.PathValue("basehead"), "...")
		write(w, map[string]any{"merge_base_commit": map[string]any{"sha": base}})
	})
	mux.HandleFunc("GET /repos/o/r/pulls/{n}/files", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.PathValue("n"))
		g.mu.Lock()
		defer g.mu.Unlock()
		write(w, g.prFiles[n])
	})
	mux.HandleFunc("GET /repos/o/r/pulls/{n}", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.PathValue("n"))
		g.mu.Lock()
		defer g.mu.Unlock()
		write(w, map[string]any{"number": n, "head": map[string]any{"sha": g.heads[n]}})
	})
	mux.HandleFunc("GET /repos/o/r/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		sha, ok := g.baseFiles[r.PathValue("path")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			write(w, map[string]any{"message": "Not Found"})
			return
		}
		write(w, map[string]any{"type": "file", "path": r.PathValue("path"), "sha": sha, "size": len(g.blobs[sha]),
			"encoding": "base64", "content": base64.StdEncoding.EncodeToString(g.blobs[sha])})
	})
	mux.HandleFunc("GET /repos/o/r/git/blobs/{sha}", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		b, ok := g.blobs[r.PathValue("sha")]
		if !ok || r.Header.Get("Accept") != "application/vnd.github.raw" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(b)
	})
	mux.HandleFunc("POST /repos/o/r/check-runs", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		defer g.mu.Unlock()
		g.nextID++
		g.checks[g.nextID] = body
		w.WriteHeader(http.StatusCreated)
		write(w, map[string]any{"id": g.nextID})
	})
	mux.HandleFunc("PATCH /repos/o/r/check-runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		defer g.mu.Unlock()
		for k, v := range body {
			g.checks[id][k] = v
		}
		write(w, map[string]any{"id": id})
	})
	comment := func(id int64, body string) map[string]any {
		return map[string]any{"id": id, "body": body, "user": map[string]any{"login": "depguard[bot]", "type": "Bot"}}
	}
	mux.HandleFunc("GET /repos/o/r/issues/{n}/comments", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		out := []any{map[string]any{"id": 1, "body": render.Marker + " spoof", "user": map[string]any{"login": "mallory", "type": "User"}}}
		for id, b := range g.comments {
			out = append(out, comment(id, b))
		}
		write(w, out)
	})
	mux.HandleFunc("POST /repos/o/r/issues/{n}/comments", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		defer g.mu.Unlock()
		g.nextID++
		g.comments[g.nextID] = body["body"]
		g.created++
		w.WriteHeader(http.StatusCreated)
		write(w, comment(g.nextID, body["body"]))
	})
	mux.HandleFunc("PATCH /repos/o/r/issues/comments/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		defer g.mu.Unlock()
		if _, ok := g.comments[id]; !ok {
			w.WriteHeader(http.StatusNotFound)
			write(w, map[string]any{"message": "Not Found"})
			return
		}
		g.comments[id] = body["body"]
		g.updated++
		write(w, comment(id, body["body"]))
	})
	mux.HandleFunc("GET /repos/o/r/git/trees/{sha}", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		entry := func(p, sha string) map[string]any {
			return map[string]any{"path": p, "type": "blob", "sha": sha, "size": len(g.blobs[sha])}
		}
		write(w, map[string]any{"sha": r.PathValue("sha"), "tree": []any{entry("package-lock.json", "head1"),
			entry("node_modules/dep/package-lock.json", "head1"), entry("src/main.js", "x")}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		panic(fmt.Sprintf("unexpected GitHub call %s %s %s", r.Method, r.URL, body))
	})
	return mux
}

// setPR sets a PR's head lockfile (and base lockfile at the merge base).
func (g *fakeGitHub) setPR(pr int, head string, files []map[string]string, blobs map[string][]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.heads[pr] = head
	g.prFiles[pr] = files
	for k, v := range blobs {
		g.blobs[k] = v
	}
}

func testKey(t *testing.T) []byte {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func TestPullRequestEndToEnd(t *testing.T) {
	ctx := context.Background()
	pg := testpg.Start(t)
	_, err := pg.Owner.Exec(ctx, `
		INSERT INTO tenant_settings (tenant_id, domain, block_mode, suppress_clean_comments) VALUES ('t1','t1.example',true,true);
		INSERT INTO gh_installations (id, account_login, account_type, account_id, tenant_id, status) VALUES (10,'o','Organization',1,'t1','linked');`)
	if err != nil {
		t.Fatal(err)
	}

	gh := newFakeGitHub()
	srv := httptest.NewServer(gh.handler())
	defer srv.Close()
	cfg := ghapp.Config{AppID: 1, Slug: "depguard", PrivateKey: testKey(t), APIURL: srv.URL + "/"}
	clients, err := ghapp.NewClientCreator(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// A fake guarddog flags everything it sees.
	gd := filepath.Join(t.TempDir(), "guarddog")
	os.WriteFile(gd, []byte("#!/bin/sh\necho '{\"issues\":1,\"errors\":{},\"results\":{\"npm-install-script\":\"curl | sh\"}}'\n"), 0o755)

	workers := river.NewWorkers()
	AddWorkers(workers, Deps{Pool: pg.App, Clients: clients, GitHub: cfg, PublicURL: "https://app.example",
		GuarddogBin: gd, DisableXBOM: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Enricher: fakeEnricher{"evil-pkg": {"MAL-2025-1", "CRITICAL"}, "vuln-pkg": {"GHSA-aaaa", "HIGH"}}})
	rc, err := river.NewClient(riverpgxv5.New(pg.App), &river.Config{Queues: map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 4}}, Workers: workers})
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := rc.Subscribe(river.EventKindJobCompleted, river.EventKindJobFailed, river.EventKindJobCancelled)
	defer cancel()
	if err := rc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer rc.Stop(ctx)

	await := func(kind string) *river.Event {
		t.Helper()
		timeout := time.After(2 * time.Minute)
		for {
			select {
			case ev := <-events:
				if ev.Job.Kind != kind {
					continue
				}
				if ev.Kind != river.EventKindJobCompleted {
					t.Fatalf("%s %s: %v", kind, ev.Kind, ev.Job.Errors)
				}
				return ev
			case <-timeout:
				t.Fatalf("timeout waiting for %s", kind)
			}
		}
	}
	runPR := func(pr int, head string) {
		t.Helper()
		if _, err := rc.Insert(ctx, jobs.ScanPullRequest{InstallationID: 10, RepoID: 7, RepoFullName: "o/r", PRNumber: pr,
			BaseSHA: "base", HeadSHA: head, BaseRef: "main", HeadRef: "feat"}, nil); err != nil {
			t.Fatal(err)
		}
		await("scan_pull_request")
	}
	lastCheck := func() map[string]any {
		gh.mu.Lock()
		defer gh.mu.Unlock()
		return gh.checks[gh.nextIDCheck()]
	}

	base := npmLock("ok-pkg@1.0.0")
	gh.blobs["baseblob"] = base
	gh.baseFiles["package-lock.json"] = "baseblob"
	lockFile := func(sha string) []map[string]string {
		return []map[string]string{{"filename": "package-lock.json", "status": "modified", "sha": sha}, {"filename": "README.md", "status": "modified", "sha": "x"}}
	}

	// 1) PR adds a malicious and a vulnerable package → failure + one comment.
	gh.setPR(1, "h1", lockFile("head1"), map[string][]byte{"head1": npmLock("ok-pkg@1.0.0", "evil-pkg@1.0.0", "vuln-pkg@2.0.0")})
	runPR(1, "h1")
	if c := lastCheck(); c["conclusion"] != "failure" || c["status"] != "completed" {
		t.Fatalf("check run: %v", c)
	}
	if gh.created != 1 || gh.updated != 0 {
		t.Fatalf("comments created=%d updated=%d", gh.created, gh.updated)
	}
	var body string
	for _, b := range gh.comments {
		body = b
	}
	if !strings.Contains(body, "evil-pkg @ 1.0.0") || !strings.Contains(body, "Malware-Fail") || strings.Contains(body, "ok-pkg") {
		t.Fatalf("comment body:\n%s", body)
	}
	var status, concl string
	var mal, viol, comps int
	var commentID *int64
	err = pg.Owner.QueryRow(ctx, `SELECT status, conclusion, malicious_count, violations_count, components_count, comment_id FROM scans
		WHERE pr_number=1 AND head_sha='h1'`).Scan(&status, &concl, &mal, &viol, &comps, &commentID)
	if err != nil || status != "success" || concl != "failure" || mal != 1 || viol != 2 || comps != 2 || commentID == nil {
		t.Fatalf("scan row: %v %s %s mal=%d viol=%d comps=%d", err, status, concl, mal, viol, comps)
	}
	var pvc, malicious int
	pg.Owner.QueryRow(ctx, `SELECT count(*) FROM project_version_components`).Scan(&pvc)
	pg.Owner.QueryRow(ctx, `SELECT count(*) FROM package_analyses WHERE status='malicious' AND verified AND source='osv'`).Scan(&malicious)
	if pvc != 0 || malicious != 1 {
		t.Fatalf("pvc=%d (PR scans must not touch it) malicious analyses=%d", pvc, malicious)
	}
	// Guarddog runs on the newly added non-malicious package (vuln-pkg) only.
	await("guarddog_analyze")
	var suspicious int
	pg.Owner.QueryRow(ctx, `SELECT count(*) FROM package_analyses pa JOIN components c ON c.id=pa.component_id
		WHERE pa.source='guarddog' AND pa.status='suspicious' AND c.name='vuln-pkg'`).Scan(&suspicious)
	if suspicious != 1 {
		t.Fatalf("guarddog analyses=%d", suspicious)
	}

	// 2) New head SHA → same comment edited, not a new one.
	gh.setPR(1, "h2", lockFile("head2"), map[string][]byte{"head2": npmLock("ok-pkg@1.0.0", "evil-pkg@1.0.0")})
	runPR(1, "h2")
	if gh.created != 1 || gh.updated != 1 {
		t.Fatalf("comments created=%d updated=%d", gh.created, gh.updated)
	}

	// 3) Clean PR with suppress_clean_comments → success, no comment.
	gh.setPR(2, "c1", lockFile("clean1"), map[string][]byte{"clean1": npmLock("ok-pkg@1.0.0", "fine-pkg@3.0.0")})
	runPR(2, "c1")
	if c := lastCheck(); c["conclusion"] != "success" {
		t.Fatalf("clean check: %v", c)
	}
	if gh.created != 1 {
		t.Fatalf("clean PR created a comment (%d)", gh.created)
	}

	// 4) No dependency changes → success, still no comment (suppressed).
	gh.setPR(3, "n1", []map[string]string{{"filename": "main.go", "status": "modified", "sha": "x"}}, nil)
	runPR(3, "n1")
	if c := lastCheck(); c["conclusion"] != "success" || !strings.Contains(fmt.Sprint(c["output"]), "No dependency changes") {
		t.Fatalf("no-change check: %v", c)
	}

	// 5) Head moved during the scan → results dropped, check skipped.
	gh.setPR(4, "moved", lockFile("head1"), nil)
	runPR(4, "old")
	if c := lastCheck(); c["conclusion"] != "skipped" {
		t.Fatalf("stale check: %v", c)
	}
	pg.Owner.QueryRow(ctx, `SELECT status FROM scans WHERE pr_number=4`).Scan(&status)
	if status != "skipped" {
		t.Fatalf("stale scan status %s", status)
	}

	// 6) Push to default branch → full scan replaces the version's components.
	if _, err := rc.Insert(ctx, jobs.ScanRepository{TenantID: "t1", InstallationID: 10, RepoID: 7, RepoFullName: "o/r",
		Ref: "main", SHA: "m1", Trigger: "push"}, nil); err != nil {
		t.Fatal(err)
	}
	await("scan_repository")
	var lastScan *string
	pg.Owner.QueryRow(ctx, `SELECT count(*) FROM project_version_components pvc JOIN project_versions v ON v.id=pvc.project_version_id
		WHERE v.name='main'`).Scan(&pvc)
	pg.Owner.QueryRow(ctx, `SELECT last_scan_id FROM project_versions WHERE name='main'`).Scan(&lastScan)
	pg.Owner.QueryRow(ctx, `SELECT status, conclusion, components_count FROM scans WHERE trigger='push'`).Scan(&status, &concl, &comps)
	if pvc != 3 || lastScan == nil || status != "success" || concl != "failure" || comps != 3 {
		t.Fatalf("push scan: pvc=%d last=%v %s %s comps=%d", pvc, lastScan, status, concl, comps)
	}

	// 7) CLI upload → report_md and conclusion for the CLI to print.
	_, err = pg.Owner.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, source, name) VALUES ('P','t1','cli','acme/cli');
		INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('V','t1','P','main');
		INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger) VALUES ('S','t1','P','V','cli');`)
	if err == nil {
		_, err = pg.Owner.Exec(ctx, `INSERT INTO scan_uploads (tenant_id, scan_id, path, content) VALUES ('t1','S','app/package-lock.json',$1)`,
			npmLock("vuln-pkg@2.0.0"))
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Insert(ctx, jobs.ScanUpload{TenantID: "t1", ScanID: "S"}, nil); err != nil {
		t.Fatal(err)
	}
	await("scan_upload")
	var report string
	pg.Owner.QueryRow(ctx, `SELECT status, conclusion, report_md FROM scans WHERE id='S'`).Scan(&status, &concl, &report)
	if status != "success" || concl != "failure" || !strings.Contains(report, "app/package-lock.json") {
		t.Fatalf("upload scan: %s %s\n%s", status, concl, report)
	}
}

// nextIDCheck returns the most recently created check run id. Caller holds mu.
func (g *fakeGitHub) nextIDCheck() int64 {
	var max int64
	for id := range g.checks {
		if id > max {
			max = id
		}
	}
	return max
}
