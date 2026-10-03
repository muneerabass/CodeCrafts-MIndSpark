package suspicious

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// fakePyPI serves a tiny top-pypi-packages dump and points the downloader at it.
func fakePyPI(t *testing.T) *atomic.Int32 {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		rows := []map[string]any{}
		for _, n := range []string{"requests", "python-dateutil", "numpy", "Typing_Extensions"} {
			rows = append(rows, map[string]any{"project": n, "download_count": 1})
		}
		json.NewEncoder(w).Encode(map[string]any{"rows": rows})
	}))
	t.Cleanup(srv.Close)
	old := pypiURL
	pypiURL = srv.URL
	t.Cleanup(func() { pypiURL = old; resetLists() })
	t.Setenv("DEPGUARD_DATA_DIR", t.TempDir())
	resetLists()
	return &hits
}

func resetLists() {
	listsMu.Lock()
	lists = map[string]*cachedList{}
	listsMu.Unlock()
}

func TestTyposquat(t *testing.T) {
	fakePyPI(t)
	cases := []struct {
		eco, name, similar, tech string
	}{
		{"npm", "lodahs", "lodash", TechniqueSwap},
		{"npm", "expres", "express", TechniqueDistance1},
		{"npm", "expresss", "express", TechniqueDistance1},
		{"npm", "Lodash", "", ""}, // popular (case-insensitive)
		{"npm", "lodash", "", ""}, // popular
		{"npm", "uuid", "", ""},   // popular, though 1 edit from "uid"
		{"npm", "lod", "", ""},    // too short
		{"npm", "zzqx-unrelated", "", ""},
		{"PyPI", "reqeusts", "requests", TechniqueSwap},
		{"PyPI", "request", "requests", TechniqueDistance1},
		{"PyPI", "dateutil-python", "python-dateutil", TechniqueReorder},
		{"PyPI", "dateutil_python", "python-dateutil", TechniqueReorder},
		{"PyPI", "py-dateutil", "python-dateutil", TechniqueConfusable},
		{"PyPI", "Python_Dateutil", "", ""}, // PEP 503 canonical form is popular
		{"PyPI", "typing.extensions", "", ""},
		{"Go", "github.com/stretchr/testfy", "github.com/stretchr/testify", TechniqueDistance1},
		{"Go", "gitlab.com/stretchr/testify", "github.com/stretchr/testify", TechniqueConfusable},
		{"RubyGems", "ruby-on-rails", "rails", TechniqueConfusable},
		{"Maven", "org.apache:commons", "", ""}, // no list
	}
	for _, c := range cases {
		sim, tech := Typosquat(c.eco, c.name)
		if sim != c.similar || tech != c.tech {
			t.Errorf("Typosquat(%s, %q) = %q, %q; want %q, %q", c.eco, c.name, sim, tech, c.similar, c.tech)
		}
	}
}

func TestOneEdit(t *testing.T) {
	for _, c := range []struct{ a, b, want string }{
		{"abcd", "abcd", TechniqueDistance1}, {"abcd", "abce", TechniqueDistance1}, {"abcd", "abd", TechniqueDistance1},
		{"abd", "abcd", TechniqueDistance1}, {"abcd", "bacd", TechniqueSwap}, {"abcd", "abdc", TechniqueSwap},
		{"abcd", "badc", ""}, {"abcd", "ab", ""}, {"abcd", "wxyz", ""},
	} {
		if got := oneEdit(c.a, c.b); got != c.want {
			t.Errorf("oneEdit(%q,%q)=%q want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestPyPIListCachedOnDisk(t *testing.T) {
	hits := fakePyPI(t)
	if !IsPopular("PyPI", "numpy") {
		t.Fatal("numpy not loaded")
	}
	if _, err := os.Stat(filepath.Join(DataDir(), pypiFile)); err != nil {
		t.Fatal(err)
	}
	resetLists() // a new process reads the file, no download
	if !IsPopular("PyPI", "numpy") || hits.Load() != 1 {
		t.Fatalf("hits=%d", hits.Load())
	}
}

func TestPyPIDownloadFailureIsEmpty(t *testing.T) {
	fakePyPI(t)
	pypiURL = "http://127.0.0.1:1/unreachable"
	if sim, _ := Typosquat("PyPI", "reqeusts"); sim != "" {
		t.Fatalf("got %q without a list", sim)
	}
}
