// Package suspicious flags risky packages beyond known advisories: lookalike
// (typosquat) names, deprecated and unmaintained packages, brand-new releases
// and packages without a source repository. The typosquat algorithm is a Go
// port of Datadog guarddog's (Apache-2.0), see data/README.md.
package suspicious

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

//go:embed data/top_npm_packages.json data/top_go_packages.json data/top_rubygems_packages.json
var dataFS embed.FS

// Embedded top-package lists per OSV ecosystem. PyPI's list has no clear
// redistribution license, so it is downloaded at runtime (see pypiNames).
var embedded = map[string]string{
	"npm":      "data/top_npm_packages.json",
	"Go":       "data/top_go_packages.json",
	"RubyGems": "data/top_rubygems_packages.json",
}

// pypiURL serves {"rows":[{"project": "..."}]}; "off" disables the download.
var pypiURL = envOr("DEPGUARD_TOP_PYPI_URL", "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json")

const (
	minNameLen  = 4
	pypiFile    = "top-pypi-packages.min.json"
	pypiRefresh = 30 * 24 * time.Hour
	retryAfter  = time.Hour // after a failed PyPI download
)

// Typosquat techniques (Finding.Details["technique"]).
const (
	TechniqueDistance1  = "distance-1"
	TechniqueSwap       = "swap"
	TechniqueReorder    = "reorder"
	TechniqueConfusable = "confusable"
)

type form struct{ form, popular string }

type topList struct {
	names   []string          // normalized, most popular first
	set     map[string]bool   // normalized names
	reorder map[string]string // sorted name parts -> popular name
	forms   []form            // ecosystem confusable forms of popular names
}

var (
	listsMu sync.Mutex
	lists   = map[string]*cachedList{}
)

type cachedList struct {
	l     *topList
	until time.Time
}

// Typosquat reports the popular package that name (in OSV ecosystem eco)
// imitates and the technique, or "" when it looks fine. Names shorter than 4
// characters and names that are themselves popular are never flagged.
func Typosquat(eco, name string) (similarTo, technique string) {
	n := normalize(eco, name)
	if len(n) < minNameLen {
		return "", ""
	}
	l := list(eco)
	if l == nil || l.set[n] {
		return "", ""
	}
	for _, p := range l.names {
		if t := oneEdit(n, p); t != "" && !sameOwner(eco, n, p) {
			return p, t
		}
	}
	if p, ok := l.reorder[partsKey(n)]; ok && !sameOwner(eco, n, p) {
		return p, TechniqueReorder
	}
	for _, f := range l.forms {
		if oneEdit(n, f.form) != "" && !sameOwner(eco, n, f.popular) {
			return f.popular, TechniqueConfusable
		}
	}
	return "", ""
}

// sameOwner reports whether two names live under the same publisher namespace,
// where only that publisher can release packages: Go modules under the same
// host/owner (github.com/mholt/archives vs github.com/mholt/archiver) and npm
// packages in the same @scope. A lookalike from the same owner is not a typosquat.
func sameOwner(eco, a, b string) bool {
	switch eco {
	case "Go":
		pa, pb := strings.Split(a, "/"), strings.Split(b, "/")
		return len(pa) >= 3 && len(pb) >= 3 && pa[0] == pb[0] && pa[1] == pb[1]
	case "npm":
		sa, _, okA := strings.Cut(a, "/")
		sb, _, okB := strings.Cut(b, "/")
		return okA && okB && strings.HasPrefix(sa, "@") && sa == sb
	}
	return false
}

// IsPopular reports whether name is on the ecosystem's top-package list.
func IsPopular(eco, name string) bool {
	l := list(eco)
	return l != nil && l.set[normalize(eco, name)]
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// normalize lowercases (npm, Go, RubyGems compare case-insensitively) and
// applies PEP 503 canonicalization for PyPI.
func normalize(eco, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if eco == "PyPI" {
		n = pypiSep.ReplaceAllString(n, "-")
	}
	return n
}

// oneEdit returns TechniqueDistance1 when a and b are at most one
// insertion/deletion/substitution apart, TechniqueSwap for one adjacent
// transposition, else "".
func oneEdit(a, b string) string {
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return ""
	}
	i := 0
	for i < la && i < lb && a[i] == b[i] {
		i++
	}
	switch {
	case la == lb:
		if i == la || a[i+1:] == b[i+1:] {
			return TechniqueDistance1
		}
		if i+1 < la && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:] {
			return TechniqueSwap
		}
	case la > lb:
		if a[i+1:] == b[i:] {
			return TechniqueDistance1
		}
	default:
		if b[i+1:] == a[i:] {
			return TechniqueDistance1
		}
	}
	return ""
}

// partsKey is the order-independent key of a hyphen/underscore-separated
// name ("" for single-part names). guarddog compares one-edit against every
// permutation; exact reordering covers the attack without factorial cost.
func partsKey(n string) string {
	parts := strings.FieldsFunc(n, func(r rune) bool { return r == '-' || r == '_' })
	if len(parts) < 2 {
		return ""
	}
	slices.Sort(parts)
	return strings.Join(parts, "-")
}

// confusablePairs are {long, short} term swaps per ecosystem.
var confusablePairs = map[string][2]string{
	"PyPI":     {"python", "py"},
	"Go":       {"golang", "go"},
	"RubyGems": {"ruby", "rb"},
}

// confusedForms ports guarddog's _get_confused_forms: py↔python,
// go↔golang, rb↔ruby as a term prefix/suffix (and dropping the term when it
// is exactly that word), github.com/↔gitlab.com/, rails↔ruby-on-rails.
// npm's lowercase form is handled by normalize.
func confusedForms(eco, p string) []string {
	var out []string
	switch {
	case eco == "Go" && strings.HasPrefix(p, "github.com/"):
		out = append(out, "gitlab.com/"+p[len("github.com/"):])
	case eco == "Go" && strings.HasPrefix(p, "gitlab.com/"):
		out = append(out, "github.com/"+p[len("gitlab.com/"):])
	case eco == "RubyGems" && p == "rails":
		out = append(out, "ruby-on-rails")
	case eco == "RubyGems" && p == "ruby-on-rails":
		out = append(out, "rails")
	}
	pair, ok := confusablePairs[eco]
	if !ok {
		return out
	}
	long, short := pair[0], pair[1]
	terms := strings.Split(p, "-")
	for i, t := range terms {
		var c string
		switch {
		case strings.HasPrefix(t, long):
			c = short + t[len(long):]
		case strings.HasSuffix(t, long):
			c = t[:len(t)-len(long)] + short
		case strings.HasPrefix(t, short):
			c = long + t[len(short):]
		case strings.HasSuffix(t, short):
			c = t[:len(t)-len(short)] + long
		default:
			continue
		}
		out = append(out, strings.Join(slices.Concat(terms[:i], []string{c}, terms[i+1:]), "-"))
		if (t == long || t == short) && len(terms) > 1 {
			out = append(out, strings.Join(slices.Concat(terms[:i], terms[i+1:]), "-"))
		}
	}
	return out
}

func newTopList(eco string, names []string) *topList {
	l := &topList{set: map[string]bool{}, reorder: map[string]string{}}
	for _, raw := range names {
		n := normalize(eco, raw)
		if n == "" || l.set[n] {
			continue
		}
		l.set[n] = true
		l.names = append(l.names, n)
		if k := partsKey(n); k != "" {
			if _, ok := l.reorder[k]; !ok {
				l.reorder[k] = n
			}
		}
	}
	for _, n := range l.names {
		for _, f := range confusedForms(eco, n) {
			if len(f) >= minNameLen && f != n {
				l.forms = append(l.forms, form{f, n})
			}
		}
	}
	return l
}

// list returns the (lazily loaded) top list for eco, nil if unsupported.
// ponytail: one global lock, so the first PyPI download (≤30s) stalls other
// lookups; per-ecosystem locks if that ever shows up in scan latency.
func list(eco string) *topList {
	listsMu.Lock()
	defer listsMu.Unlock()
	if c := lists[eco]; c != nil && time.Now().Before(c.until) {
		return c.l
	}
	var names []string
	until := time.Now().Add(100 * 365 * 24 * time.Hour)
	if f, ok := embedded[eco]; ok {
		b, _ := dataFS.ReadFile(f)
		var doc struct {
			Packages []string `json:"packages"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			panic(fmt.Sprintf("suspicious: embedded %s: %v", f, err))
		}
		names = doc.Packages
	} else if eco == "PyPI" {
		names = pypiNames()
		until = time.Now().Add(pypiRefresh)
		if len(names) == 0 {
			until = time.Now().Add(retryAfter)
		}
	} else {
		return nil
	}
	l := newTopList(eco, names)
	lists[eco] = &cachedList{l, until}
	return l
}

// DataDir is where runtime-downloaded lists are cached: $DEPGUARD_DATA_DIR,
// default <os temp dir>/depguard.
func DataDir() string {
	if d := os.Getenv("DEPGUARD_DATA_DIR"); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), "depguard")
}

// pypiNames reads the cached hugovk/top-pypi-packages dump, downloading it
// when missing or older than 30 days. A failed download falls back to the
// stale copy, else to an empty list (no PyPI typosquat detection).
func pypiNames() []string {
	path := filepath.Join(DataDir(), pypiFile)
	fi, statErr := os.Stat(path)
	if (statErr != nil || time.Since(fi.ModTime()) > pypiRefresh) && pypiURL != "off" {
		if err := download(pypiURL, path); err != nil {
			slog.Warn("suspicious: top PyPI packages download failed", "url", pypiURL, "err", err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Rows []struct {
			Project string `json:"project"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		slog.Warn("suspicious: bad top PyPI packages file", "path", path, "err", err)
		return nil
	}
	names := make([]string, 0, len(doc.Rows))
	for _, r := range doc.Rows {
		names = append(names, r.Project)
	}
	return names
}

func download(url, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if !json.Valid(b) {
		return fmt.Errorf("invalid JSON")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pypi-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
