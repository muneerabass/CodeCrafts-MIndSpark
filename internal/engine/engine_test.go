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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/engine/testpg"
	"github.com/depguard/depguard/internal/ghapp"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/render"
	"github.com/depguard/depguard/internal/scan"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

// npmLock builds a minimal package-lock.json (v3) for "name@version" args.
// "name@version:a,b" adds dependencies on packages a and b; a leading "~"
// makes the package transitive-only (not a dependency of the app).
func npmLock(pkgs ...string) []byte {
	deps := map[string]string{}
	packages := map[string]any{}
	for _, p := range pkgs {
		p, transitive := strings.CutPrefix(p, "~")
		p, children, _ := strings.Cut(p, ":")
		name, ver, _ := strings.Cut(p, "@")
		if !transitive {
			deps[name] = ver
		}
		entry := map[string]any{"version": ver,
			"resolved": fmt.Sprintf("https://registry.npmjs.org/%s/-/%s-%s.tgz", name, name, ver)}
		if children != "" {
			cd := map[string]string{}
			for _, c := range strings.Split(children, ",") {
				cd[c] = "*"
			}
			entry["dependencies"] = cd
		}
		packages["node_modules/"+name] = entry
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
	labels    map[int][]string // PR -> labels
	nextID    int64
	tree      map[string]string // path -> blob sha of every commit's tree
	license   string            // GET /license spdx_id; "" = 404
	fixTree   []any             // entries of the last created tree
	fixRef    string            // last created ref
	fixPR     map[string]any    // last created pull request
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{blobs: map[string][]byte{}, baseFiles: map[string]string{}, prFiles: map[int][]map[string]string{},
		heads: map[int]string{}, checks: map[int64]map[string]any{}, comments: map[int64]string{}, labels: map[int][]string{}, nextID: 100,
		tree: map[string]string{"package-lock.json": "head1", "node_modules/dep/package-lock.json": "head1", "src/main.js": "x"}}
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
	mux.HandleFunc("GET /repos/o/r/issues/{n}/labels", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.PathValue("n"))
		g.mu.Lock()
		defer g.mu.Unlock()
		out := []any{map[string]any{"name": "team-label"}}
		for _, l := range g.labels[n] {
			out = append(out, map[string]any{"name": l})
		}
		write(w, out)
	})
	mux.HandleFunc("POST /repos/o/r/labels", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		write(w, map[string]any{"name": "x"})
	})
	mux.HandleFunc("POST /repos/o/r/issues/{n}/labels", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.PathValue("n"))
		var add []string
		json.NewDecoder(r.Body).Decode(&add)
		g.mu.Lock()
		defer g.mu.Unlock()
		g.labels[n] = append(g.labels[n], add...)
		write(w, []any{})
	})
	mux.HandleFunc("DELETE /repos/o/r/issues/{n}/labels/{name}", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.PathValue("n"))
		g.mu.Lock()
		defer g.mu.Unlock()
		g.labels[n] = slices.DeleteFunc(g.labels[n], func(l string) bool { return l == r.PathValue("name") })
		write(w, []any{})
	})
	mux.HandleFunc("GET /repos/o/r/git/trees/{sha}", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		var tree []any
		for p, sha := range g.tree {
			tree = append(tree, map[string]any{"path": p, "type": "blob", "sha": sha, "size": len(g.blobs[sha])})
		}
		write(w, map[string]any{"sha": r.PathValue("sha"), "tree": tree})
	})
	mux.HandleFunc("GET /repos/o/r/branches/{b}", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]any{"name": r.PathValue("b"), "commit": map[string]any{"sha": "mainsha", "commit": map[string]any{"tree": map[string]any{"sha": "maintree"}}}})
	})
	mux.HandleFunc("POST /repos/o/r/git/trees", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		g.mu.Lock()
		g.fixTree, _ = b["tree"].([]any)
		g.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		write(w, map[string]any{"sha": "newtree"})
	})
	mux.HandleFunc("POST /repos/o/r/git/commits", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		write(w, map[string]any{"sha": "fixcommit"})
	})
	mux.HandleFunc("POST /repos/o/r/git/refs", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		g.mu.Lock()
		g.fixRef, _ = b["ref"].(string)
		g.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		write(w, b)
	})
	mux.HandleFunc("POST /repos/o/r/pulls", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		g.mu.Lock()
		g.fixPR = b
		g.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		write(w, map[string]any{"number": 77, "html_url": "https://github.com/o/r/pull/77"})
	})
	mux.HandleFunc("GET /repos/o/r/license", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.license == "" {
			w.WriteHeader(http.StatusNotFound)
			write(w, map[string]any{"message": "Not Found"})
			return
		}
		write(w, map[string]any{"name": "LICENSE", "license": map[string]any{"key": "x", "spdx_id": g.license}})
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

// harness runs the engine's workers against testpg and a fake GitHub.
type harness struct {
	pg     testpg.DB
	gh     *fakeGitHub
	rc     *river.Client[pgx.Tx]
	events <-chan *river.Event
}

// newHarness seeds tenant t1 (block mode, suppressed clean comments) linked
// to installation 10. guarddogOut is the fake guarddog's JSON output.
func newHarness(t *testing.T, guarddogOut string, mod func(*Deps)) *harness {
	t.Helper()
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
	t.Cleanup(srv.Close)
	cfg := ghapp.Config{AppID: 1, Slug: "depguard", PrivateKey: testKey(t), APIURL: srv.URL + "/"}
	clients, err := ghapp.NewClientCreator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	gd := filepath.Join(t.TempDir(), "guarddog")
	os.WriteFile(gd, []byte("#!/bin/sh\necho '"+guarddogOut+"'\n"), 0o755)

	workers := river.NewWorkers()
	d := Deps{Pool: pg.App, Clients: clients, GitHub: cfg, PublicURL: "https://app.example",
		GuarddogBin: gd, DisableXBOM: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Enricher: fakeEnricher{"evil-pkg": {"MAL-2025-1", "CRITICAL"}, "vuln-pkg": {"GHSA-aaaa", "HIGH"}}}
	if mod != nil {
		mod(&d)
	}
	AddWorkers(workers, d)
	rc, err := river.NewClient(riverpgxv5.New(pg.App), &river.Config{Queues: map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 4}}, Workers: workers})
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := rc.Subscribe(river.EventKindJobCompleted, river.EventKindJobFailed, river.EventKindJobCancelled)
	t.Cleanup(cancel)
	if err := rc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rc.Stop(context.Background()) })
	return &harness{pg: pg, gh: gh, rc: rc, events: events}
}

// await waits for the next completed job of kind.
func (h *harness) await(t *testing.T, kind string) *river.Event {
	t.Helper()
	timeout := time.After(2 * time.Minute)
	for {
		select {
		case ev := <-h.events:
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

func TestPullRequestEndToEnd(t *testing.T) {
	ctx := context.Background()
	// A fake guarddog flags everything it sees.
	h := newHarness(t, `{"issues":1,"errors":{},"results":{"npm-install-script":"curl | sh"}}`, nil)
	pg, gh, rc := h.pg, h.gh, h.rc
	await := func(kind string) *river.Event { t.Helper(); return h.await(t, kind) }
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
	if gh.created != 1 {
		t.Fatalf("comments created=%d updated=%d", gh.created, gh.updated)
	}
	var body string
	for _, b := range gh.comments {
		body = b
	}
	for _, want := range []string{"evil-pkg @ 1.0.0", `alt="MALWARE: fail"`, "Remove malicious package", "npm uninstall evil-pkg",
		"Fix Before Merging", "blocking issue", "depguard Report Summary", render.RerunMarker, "View complete scan results"} {
		if !strings.Contains(body, want) {
			t.Fatalf("comment body lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "ok-pkg") {
		t.Fatalf("unchanged package in comment:\n%s", body)
	}
	// The PR is recorded, ranked critical (malware) and labelled on GitHub, keeping the team's own label.
	var level, prTitle string
	var urgency int
	var prLabels []string
	err := pg.Owner.QueryRow(ctx, `SELECT urgency_level, urgency, labels, title FROM pull_requests WHERE repo_id=7 AND number=1`).Scan(&level, &urgency, &prLabels, &prTitle)
	if err != nil || level != "critical" || urgency != 100 || !slices.Contains(prLabels, "malware") || !slices.Contains(prLabels, "blocked") {
		t.Fatalf("pull_requests row: %v level=%s urgency=%d labels=%v", err, level, urgency, prLabels)
	}
	gh.mu.Lock()
	ghLabels := slices.Clone(gh.labels[1])
	gh.mu.Unlock()
	if !slices.Contains(ghLabels, "depguard:malware") || !slices.Contains(ghLabels, "depguard:blocked") || !slices.Contains(ghLabels, "depguard:urgent") {
		t.Fatalf("GitHub labels %v", ghLabels)
	}
	// Rule-based review stored for the head commit; AI review skipped (no model configured).
	var aiStatus string
	pg.Owner.QueryRow(ctx, `SELECT r.ai_status FROM pr_reviews r JOIN pull_requests p ON p.id=r.pr_id WHERE p.number=1 AND r.head_sha='h1'`).Scan(&aiStatus)
	if aiStatus != "skipped" {
		t.Fatalf("review ai_status %q", aiStatus)
	}
	var status, concl string
	var mal, viol, comps int
	var commentID *int64
	err = pg.Owner.QueryRow(ctx, `SELECT status, conclusion, malicious_count, violations_count, components_count, comment_id FROM scans
		WHERE pr_number=1 AND head_sha='h1'`).Scan(&status, &concl, &mal, &viol, &comps, &commentID)
	if err != nil || status != "success" || concl != "failure" || mal != 1 || viol != 2 || comps != 2 || commentID == nil {
		t.Fatalf("scan row: %v %s %s mal=%d viol=%d comps=%d", err, status, concl, mal, viol, comps)
	}
	// PR scans record graph context per package (here a direct dependency).
	var direct *bool
	var depth *int
	var via []string
	var source string
	err = pg.Owner.QueryRow(ctx, `SELECT sp.direct, sp.depth, sp.via, sp.graph_source FROM scan_packages sp
		JOIN components c ON c.id=sp.component_id JOIN scans s ON s.id=sp.scan_id
		WHERE c.name='vuln-pkg' AND s.head_sha='h1'`).Scan(&direct, &depth, &via, &source)
	if err != nil || direct == nil || !*direct || depth == nil || *depth != 1 || fmt.Sprint(via) != "[vuln-pkg@2.0.0]" || source != "lockfile" {
		t.Fatalf("PR scan_packages: %v direct=%v depth=%v via=%v source=%s", err, direct, depth, via, source)
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
	updatedBefore := gh.updated
	gh.setPR(1, "h2", lockFile("head2"), map[string][]byte{"head2": npmLock("ok-pkg@1.0.0", "evil-pkg@1.0.0")})
	runPR(1, "h2")
	if gh.created != 1 || gh.updated <= updatedBefore {
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

// fakeChecker flags typo-pkg (non-blocking) and records what it was given.
type fakeChecker struct {
	mu       sync.Mutex
	projects []scan.Project
	deep     scan.PackageContext // context passed for vuln-deep
}

func (c *fakeChecker) Name() string { return "fake" }

func (c *fakeChecker) Check(_ context.Context, in scan.CheckInput) ([]scan.Finding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.projects = append(c.projects, in.Project)
	var out []scan.Finding
	for _, p := range in.Packages {
		if p.GetName() == "vuln-deep" {
			c.deep = in.Context[p]
		}
		if p.GetName() == "typo-pkg" {
			out = append(out, scan.Finding{Rule: "typosquat", Category: scan.CategorySuspicious, Severity: scan.SeverityMedium,
				Summary: "typo-pkg looks like type-pkg", Details: map[string]any{"similar_to": "type-pkg"}, Package: p})
		}
	}
	return out, nil
}

func TestRiskAnalysisEndToEnd(t *testing.T) {
	ctx := context.Background()
	fc := &fakeChecker{}
	h := newHarness(t, `{"issues":0,"errors":{},"results":{}}`, func(d *Deps) {
		d.Enricher = fakeEnricher{"vuln-deep": {"GHSA-deep", "HIGH"}}
		d.Checkers = func(scan.PolicyConfig, scan.Project) []scan.Checker { return []scan.Checker{fc} }
		d.DetectLicense = func(files map[string][]byte, spdx string) (string, string) {
			if _, ok := files["LICENSE"]; ok {
				return "MIT", "license_file"
			}
			if spdx != "" {
				return spdx, "github"
			}
			return "", "unknown"
		}
	})
	pg, gh := h.pg, h.gh
	lock := npmLock("app-dep@1.0.0:mid-pkg", "dev-tool@1.0.0", "typo-pkg@1.0.0", "~mid-pkg@1.0.0:vuln-deep", "~vuln-deep@1.0.0")
	pkgJSON := []byte(`{"dependencies":{"app-dep":"^1","typo-pkg":"1"},"devDependencies":{"dev-tool":"1"}}`)
	gh.mu.Lock()
	gh.blobs = map[string][]byte{"lock": lock, "pj": pkgJSON, "lic": []byte("MIT License ..."),
		"js": []byte("import dep from 'app-dep';\nconst x = require('./local');\n")}
	gh.tree = map[string]string{"package-lock.json": "lock", "package.json": "pj", "LICENSE": "lic", "src/index.js": "js"}
	gh.license = "Apache-2.0"
	gh.mu.Unlock()

	// 1) Full scan: graph context, edges, findings, detected license.
	if _, err := h.rc.Insert(ctx, jobs.ScanRepository{TenantID: "t1", InstallationID: 10, RepoID: 7, RepoFullName: "o/r",
		Ref: "main", SHA: "m1", Trigger: "push"}, nil); err != nil {
		t.Fatal(err)
	}
	h.await(t, "scan_repository")
	type row struct {
		direct, dev, imported *bool
		depth                 *int
		via                   []string
		paths                 [][]string
		source                string
	}
	pkgRow := func(scanCond, name string) row {
		t.Helper()
		var r row
		err := pg.Owner.QueryRow(ctx, `SELECT sp.direct, sp.dev, sp.imported, sp.depth, sp.via, sp.paths, sp.graph_source
			FROM scan_packages sp JOIN components c ON c.id=sp.component_id JOIN scans s ON s.id=sp.scan_id
			WHERE `+scanCond+` AND c.name=$1`, name).Scan(&r.direct, &r.dev, &r.imported, &r.depth, &r.via, &r.paths, &r.source)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return r
	}
	b := func(p *bool) string { return fmt.Sprint(p != nil && *p, p == nil) } // "value isNil"
	deep := pkgRow("s.trigger='push'", "vuln-deep")
	if b(deep.direct) != "false false" || *deep.depth != 3 || b(deep.dev) != "false false" || b(deep.imported) != "true false" ||
		fmt.Sprint(deep.via) != "[app-dep@1.0.0 mid-pkg@1.0.0 vuln-deep@1.0.0]" ||
		fmt.Sprint(deep.paths) != "[[app-dep@1.0.0 mid-pkg@1.0.0 vuln-deep@1.0.0]]" || deep.source != "lockfile" {
		t.Fatalf("vuln-deep row: %+v direct=%s dev=%s imported=%s", deep, b(deep.direct), b(deep.dev), b(deep.imported))
	}
	dev := pkgRow("s.trigger='push'", "dev-tool")
	if b(dev.direct) != "true false" || *dev.depth != 1 || b(dev.dev) != "true false" || b(dev.imported) != "false false" {
		t.Fatalf("dev-tool row: direct=%s dev=%s imported=%s", b(dev.direct), b(dev.dev), b(dev.imported))
	}
	if fc.deep.Depth != 3 || fc.deep.Direct == nil || *fc.deep.Direct || fc.deep.Imported == nil || !*fc.deep.Imported {
		t.Fatalf("checker context for vuln-deep: %+v", fc.deep)
	}
	var edges []string
	rows, err := pg.Owner.Query(ctx, `SELECT coalesce(p.name, 'app') || '>' || c.name FROM project_version_dependencies d
		JOIN components c ON c.id=d.child_component_id LEFT JOIN components p ON p.id=d.parent_component_id ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var e string
		rows.Scan(&e)
		edges = append(edges, e)
	}
	rows.Close()
	if fmt.Sprint(edges) != "[app-dep>mid-pkg app>app-dep app>dev-tool app>typo-pkg mid-pkg>vuln-deep]" {
		t.Fatalf("edges %v", edges)
	}
	var pvcDirect, pvcDepth int
	pg.Owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE direct), max(depth) FROM project_version_components`).Scan(&pvcDirect, &pvcDepth)
	if pvcDirect != 3 || pvcDepth != 3 {
		t.Fatalf("project_version_components direct=%d max depth=%d", pvcDirect, pvcDepth)
	}
	viol := func(scanCond string) []string {
		t.Helper()
		rows, err := pg.Owner.Query(ctx, `SELECT v.rule_name || ':' || v.category || ':' || v.severity || ':' || v.blocking || ':' || v.details::text
			FROM policy_violations v JOIN scans s ON s.id=v.scan_id WHERE `+scanCond+` ORDER BY 1`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var v string
			rows.Scan(&v)
			out = append(out, v)
		}
		return out
	}
	if v := viol("s.trigger='push'"); fmt.Sprint(v) != `[critical-or-high-vulnerability:vulnerability:high:true:{} typosquat:suspicious:medium:false:{"similar_to": "type-pkg"}]` {
		t.Fatalf("push violations %q", v)
	}
	var concl, lic, licSrc string
	var suspicious int
	pg.Owner.QueryRow(ctx, `SELECT conclusion, suspicious_count FROM scans WHERE trigger='push'`).Scan(&concl, &suspicious)
	if suspicious != 1 {
		t.Fatalf("push suspicious_count=%d, want 1 (typosquat finding)", suspicious)
	}
	pg.Owner.QueryRow(ctx, `SELECT license, license_source FROM projects WHERE name='o/r'`).Scan(&lic, &licSrc)
	if concl != "failure" || lic != "MIT" || licSrc != "license_file" || fc.projects[0].License != "MIT" {
		t.Fatalf("push conclusion=%s license=%s/%s checker project=%+v", concl, lic, licSrc, fc.projects)
	}

	// 2) Upload with only a non-blocking finding → neutral, not failure. The
	// project's license override wins over detection and is not replaced.
	_, err = pg.Owner.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, source, name, license, license_source, usage_model) VALUES ('P','t1','cli','acme/cli','Apache-2.0','override','saas');
		INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('V','t1','P','main');
		INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger) VALUES ('S','t1','P','V','cli');`)
	if err == nil {
		_, err = pg.Owner.Exec(ctx, `INSERT INTO scan_uploads (tenant_id, scan_id, path, content) VALUES ('t1','S','LICENSE','MIT License'),
		  ('t1','S','package.json',$1), ('t1','S','package-lock.json',$2)`, pkgJSON, npmLock("typo-pkg@1.0.0"))
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.rc.Insert(ctx, jobs.ScanUpload{TenantID: "t1", ScanID: "S"}, nil); err != nil {
		t.Fatal(err)
	}
	h.await(t, "scan_upload")
	var status string
	pg.Owner.QueryRow(ctx, `SELECT status, conclusion FROM scans WHERE id='S'`).Scan(&status, &concl)
	pg.Owner.QueryRow(ctx, `SELECT license, license_source FROM projects WHERE id='P'`).Scan(&lic, &licSrc)
	last := fc.projects[len(fc.projects)-1]
	if status != "success" || concl != "neutral" || lic != "Apache-2.0" || licSrc != "override" ||
		last.License != "Apache-2.0" || last.UsageModel != "saas" {
		t.Fatalf("upload: %s %s license=%s/%s checker project=%+v", status, concl, lic, licSrc, last)
	}
	typo := pkgRow("s.id='S'", "typo-pkg")
	if b(typo.direct) != "true false" || b(typo.imported) != "false true" {
		t.Fatalf("upload typo-pkg: direct=%s imported=%s", b(typo.direct), b(typo.imported))
	}
	if v := viol("s.id='S'"); len(v) != 1 || !strings.HasPrefix(v[0], "typosquat:suspicious:medium:false") {
		t.Fatalf("upload violations %q", v)
	}
}
