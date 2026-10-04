// Package registry reads release metadata straight from package registries
// (npm, PyPI): publish time, publisher, provenance and install scripts per
// version. deps.dev lags behind brand-new releases; registries don't, and a
// release's first hours are when hijacked versions do their damage.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Version is one release of a package.
type Version struct {
	Version    string            `json:"version"`
	Published  time.Time         `json:"published"`
	Publisher  string            `json:"publisher,omitempty"`  // npm account that published it
	Provenance bool              `json:"provenance,omitempty"` // signed build provenance (npm attestations)
	Scripts    map[string]string `json:"scripts,omitempty"`    // install-time scripts only (preinstall, install, postinstall, prepare)
}

// Client fetches registry metadata; zero value uses the public registries.
type Client struct {
	HTTP    *http.Client
	NPMURL  string // default https://registry.npmjs.org
	PyPIURL string // default https://pypi.org
}

const maxDoc = 64 << 20 // packuments of huge packages (e.g. @types/node) are tens of MB

func (c *Client) get(ctx context.Context, u string, out any) error {
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("registry %s: %s", u, res.Status)
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxDoc)).Decode(out)
}

// ErrNotFound means the registry has no such package.
var ErrNotFound = fmt.Errorf("package not found in the registry")

var installScripts = []string{"preinstall", "install", "postinstall", "prepare"}

// NPM lists the releases of an npm package, oldest first.
func (c *Client) NPM(ctx context.Context, name string) ([]Version, error) {
	base := strings.TrimRight(firstNonEmpty(c.NPMURL, "https://registry.npmjs.org"), "/")
	var doc struct {
		Time     map[string]string `json:"time"`
		Versions map[string]struct {
			NpmUser struct {
				Name string `json:"name"`
			} `json:"_npmUser"`
			Scripts map[string]string `json:"scripts"`
			Dist    struct {
				Attestations *struct {
					Provenance *struct {
						PredicateType string `json:"predicateType"`
					} `json:"provenance"`
				} `json:"attestations"`
			} `json:"dist"`
		} `json:"versions"`
	}
	// Scoped names keep the @ and encode the slash: @scope%2fname.
	if err := c.get(ctx, base+"/"+strings.Replace(url.PathEscape(name), "%40", "@", 1), &doc); err != nil {
		return nil, err
	}
	var out []Version
	for v, m := range doc.Versions {
		t, err := time.Parse(time.RFC3339, doc.Time[v])
		if err != nil {
			continue
		}
		ver := Version{Version: v, Published: t, Publisher: m.NpmUser.Name,
			Provenance: m.Dist.Attestations != nil && m.Dist.Attestations.Provenance != nil}
		for _, s := range installScripts {
			if body := strings.TrimSpace(m.Scripts[s]); body != "" {
				if ver.Scripts == nil {
					ver.Scripts = map[string]string{}
				}
				ver.Scripts[s] = body
			}
		}
		out = append(out, ver)
	}
	sortVersions(out)
	return out, nil
}

// PyPI lists the releases of a PyPI project (publish time = first file upload), oldest first.
func (c *Client) PyPI(ctx context.Context, name string) ([]Version, error) {
	base := strings.TrimRight(firstNonEmpty(c.PyPIURL, "https://pypi.org"), "/")
	var doc struct {
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
			Yanked     bool   `json:"yanked"`
		} `json:"releases"`
	}
	if err := c.get(ctx, base+"/pypi/"+url.PathEscape(name)+"/json", &doc); err != nil {
		return nil, err
	}
	var out []Version
	for v, files := range doc.Releases {
		var first time.Time
		for _, f := range files {
			if t, err := time.Parse(time.RFC3339, f.UploadTime); err == nil && (first.IsZero() || t.Before(first)) {
				first = t
			}
		}
		if !first.IsZero() {
			out = append(out, Version{Version: v, Published: first})
		}
	}
	sortVersions(out)
	return out, nil
}

func sortVersions(vs []Version) {
	sort.Slice(vs, func(i, j int) bool { return vs[i].Published.Before(vs[j].Published) })
}

// Find returns the release and the one published just before it (the
// previous release, nil for the first).
func Find(vs []Version, version string) (cur, prev *Version) {
	for i := range vs {
		if vs[i].Version == version {
			if i > 0 {
				return &vs[i], &vs[i-1]
			}
			return &vs[i], nil
		}
	}
	return nil, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
