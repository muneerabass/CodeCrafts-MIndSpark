package feeds_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/feeds/feedstest"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	malRec = `{"id":"MAL-2024-1","summary":"Malicious code in evil-pkg","modified":"2024-01-01T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"npm","name":"Evil-Pkg"},"versions":["1.0.0"]}]}`
	lodashRec = `{"id":"GHSA-aaaa","summary":"Prototype pollution","details":"replaceAll(\"\\u0000\", \"\")","aliases":["CVE-2021-23337"],"modified":"2024-01-02T00:00:00Z",
	  "published":"2021-02-15T00:00:00Z",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	  "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`
	withdrawnRec = `{"id":"GHSA-bbbb","modified":"2024-01-03T00:00:00Z","withdrawn":"2024-01-03T00:00:00Z",
	  "database_specific":{"severity":"MODERATE"},"details":"nul \u0000 byte",
	  "affected":[{"package":{"ecosystem":"npm","name":"minimist"},"versions":["0.0.1"]}]}`
	// incremental update: lodash advisory now also lists a second package.
	lodashRec2 = `{"id":"GHSA-aaaa","summary":"Prototype pollution v2","aliases":["CVE-2021-23337","GHSA-zzzz"],"modified":"2024-02-01T00:00:00Z",
	  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	  "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[]},{"package":{"ecosystem":"npm","name":"lodash-es"},"versions":["4.0.0"]}]}`
	newRec = `{"id":"GHSA-cccc","modified":"2024-02-02T00:00:00Z",
	  "severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}],
	  "affected":[{"package":{"ecosystem":"npm","name":"axios"},"versions":["1.0.0"]}]}`
	ghaRec = `{"id":"GHSA-dddd","modified":"2024-01-05T00:00:00Z",
	  "affected":[{"package":{"ecosystem":"GitHub Actions","name":"tj-actions/changed-files"},"versions":["45.0.7"]}]}`
)

func mkZip(t *testing.T, recs map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range recs {
		w, err := zw.Create(name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(s string) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	return buf.Bytes()
}

// fakeFeeds serves a mutable path → body map; KEV honours If-None-Match.
type fakeFeeds struct {
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
}

func (f *fakeFeeds) set(path string, body []byte) {
	f.mu.Lock()
	f.files[path] = body
	f.mu.Unlock()
}

func (f *fakeFeeds) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits[r.URL.Path]++
	if r.URL.Path == "/kev.json" && r.Header.Get("If-None-Match") == `"kev1"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	b, ok := f.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/kev.json" {
		w.Header().Set("ETag", `"kev1"`)
	}
	w.Write(b)
}

func count(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSyncFeeds(t *testing.T) {
	pool := feedstest.Postgres(t)
	ctx := context.Background()
	ff := &fakeFeeds{files: map[string][]byte{}, hits: map[string]int{}}
	ff.set("/npm/all.zip", mkZip(t, map[string]string{"MAL-2024-1": malRec, "GHSA-aaaa": lodashRec, "GHSA-bbbb": withdrawnRec}))
	ff.set("/npm/modified_id.csv", []byte("2024-01-03T00:00:00Z,GHSA-bbbb\n2024-01-02T00:00:00Z,GHSA-aaaa\n2024-01-01T00:00:00Z,MAL-2024-1\n"))
	ff.set("/GitHub Actions/all.zip", mkZip(t, map[string]string{"GHSA-dddd": ghaRec}))
	ff.set("/GitHub Actions/modified_id.csv", []byte("2024-01-05T00:00:00Z,GHSA-dddd\n"))
	ff.set("/kev.json", []byte(`{"catalogVersion":"2024.01.01","vulnerabilities":[
		{"cveID":"CVE-2021-23337","dateAdded":"2024-01-01","knownRansomwareCampaignUse":"Known"},
		{"cveID":"CVE-2020-0001","dateAdded":"2023-05-05","knownRansomwareCampaignUse":"Unknown"}]}`))
	ff.set("/epss.csv.gz", gz("#model_version:v2025.03.14,score_date:2025-03-14T00:00:00+0000\ncve,epss,percentile\nCVE-2021-23337,0.5,0.97\nCVE-2022-9999,0.01,0.2\n"))
	srv := httptest.NewServer(ff)
	defer srv.Close()

	s := feeds.New(pool, feeds.Options{
		OSVBaseURL: srv.URL, Ecosystems: []string{"npm", "GitHub Actions"},
		KEVURL:   srv.URL + "/kev.json",
		EPSSURLs: []string{srv.URL + "/missing.csv.gz", srv.URL + "/epss.csv.gz"},
	})

	// Bootstrap from all.zip.
	if err := s.SyncAllOSV(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory`); n != 4 {
		t.Fatalf("advisories = %d, want 4", n)
	}
	var risk string
	pool.QueryRow(ctx, `SELECT risk FROM advisory WHERE id='MAL-2024-1'`).Scan(&risk)
	if risk != "CRITICAL" {
		t.Errorf("MAL risk = %s", risk)
	}
	pool.QueryRow(ctx, `SELECT risk FROM advisory WHERE id='GHSA-bbbb' AND withdrawn IS NOT NULL`).Scan(&risk)
	if risk != "MEDIUM" {
		t.Errorf("withdrawn GHSA-bbbb risk = %s", risk)
	}
	if n := count(t, pool, `SELECT count(*) FROM affected WHERE ecosystem='npm' AND name_norm='evil-pkg' AND versions = '{1.0.0}'`); n != 1 {
		t.Errorf("normalized MAL affected rows = %d", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM affected WHERE advisory_id='GHSA-aaaa' AND ranges->0->>'type' = 'SEMVER'`); n != 1 {
		t.Errorf("lodash range rows = %d", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory WHERE id='GHSA-aaaa' AND details = 'replaceAll("\u0000", "")'`); n != 1 {
		t.Errorf("escaped backslash before u0000 mangled")
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory WHERE id='GHSA-dddd' AND source='GitHub Actions'`); n != 1 {
		t.Errorf("GitHub Actions advisory missing")
	}
	if n := count(t, pool, `SELECT count(*) FROM sync_state WHERE source='osv:npm' AND cursor='2024-01-03T00:00:00Z' AND last_error IS NULL`); n != 1 {
		t.Errorf("npm cursor not recorded")
	}

	// Incremental: two newer rows; the old ones must not be refetched.
	ff.set("/npm/modified_id.csv", []byte("2024-02-02T00:00:00Z,GHSA-cccc\n2024-02-01T00:00:00Z,GHSA-aaaa\n2024-01-03T00:00:00Z,GHSA-bbbb\n2024-01-02T00:00:00Z,GHSA-aaaa\n"))
	ff.set("/npm/GHSA-aaaa.json", []byte(lodashRec2))
	ff.set("/npm/GHSA-cccc.json", []byte(newRec))
	if err := s.SyncOSV(ctx, "npm"); err != nil {
		t.Fatal(err)
	}
	if ff.hits["/npm/GHSA-bbbb.json"] != 0 || ff.hits["/npm/all.zip"] != 1 {
		t.Errorf("unexpected fetches: %v", ff.hits)
	}
	if n := count(t, pool, `SELECT count(*) FROM affected WHERE advisory_id='GHSA-aaaa'`); n != 2 {
		t.Errorf("GHSA-aaaa affected rows after update = %d, want 2 (replaced)", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM advisory_alias WHERE advisory_id='GHSA-aaaa'`); n != 2 {
		t.Errorf("GHSA-aaaa aliases = %d", n)
	}
	pool.QueryRow(ctx, `SELECT risk FROM advisory WHERE id='GHSA-cccc'`).Scan(&risk)
	if risk != "HIGH" {
		t.Errorf("GHSA-cccc risk = %s", risk)
	}
	// Re-running with nothing new is a no-op.
	if err := s.SyncOSV(ctx, "npm"); err != nil {
		t.Fatal(err)
	}
	if ff.hits["/npm/GHSA-cccc.json"] != 1 {
		t.Errorf("GHSA-cccc refetched: %d", ff.hits["/npm/GHSA-cccc.json"])
	}

	// KEV twice: second is a 304.
	for range 2 {
		if err := s.SyncKEV(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM cve_score WHERE kev AND cve='CVE-2021-23337' AND ransomware AND kev_added='2024-01-01'`); n != 1 {
		t.Errorf("kev row missing")
	}
	if n := count(t, pool, `SELECT count(*) FROM sync_state WHERE source='kev' AND etag='"kev1"' AND cursor='2024.01.01'`); n != 1 {
		t.Errorf("kev state not recorded")
	}

	// EPSS with fallback URL; merges into the KEV row.
	if err := s.SyncEPSS(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, `SELECT count(*) FROM cve_score WHERE cve='CVE-2021-23337' AND kev AND epss=0.5 AND abs(percentile-0.97)<1e-6 AND epss_date='2025-03-14'`); n != 1 {
		t.Errorf("epss merge failed")
	}
	if n := count(t, pool, `SELECT count(*) FROM cve_score`); n != 3 {
		t.Errorf("cve_score rows = %d, want 3", n)
	}

	// Failure is recorded without losing the cursor.
	delete(ff.files, "/npm/modified_id.csv")
	if err := s.SyncOSV(ctx, "npm"); err == nil {
		t.Fatal("expected error for missing modified_id.csv")
	}
	st, err := feeds.Status(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 4 {
		t.Fatalf("status rows = %d: %+v", len(st), st)
	}
	for _, x := range st {
		if x.Source == "osv:npm" && (x.LastError == nil || x.Cursor == nil || *x.Cursor != "2024-02-02T00:00:00Z") {
			t.Errorf("osv:npm status = %+v", x)
		}
	}
}
