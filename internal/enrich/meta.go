package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safedep/vet/gen/insightapi"
	"golang.org/x/sync/errgroup"
)

// OSV ecosystem → deps.dev system.
var depsDevSystems = map[string]string{
	"npm": "npm", "PyPI": "pypi", "Go": "go", "Maven": "maven",
	"crates.io": "cargo", "RubyGems": "rubygems", "NuGet": "nuget",
}

type metaKey struct {
	key
	version string
}

type pkgMeta struct {
	licenses     []string
	repo         string
	stars, forks *int
	published    *time.Time
}

var errNotFound = errors.New("not found")

func (e *Enricher) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := e.o.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return json.NewDecoder(resp.Body).Decode(out)
	case http.StatusNotFound:
		return errNotFound
	}
	return fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
}

// parallel runs fn for i in [0,n) with bounded concurrency.
func (e *Enricher) parallel(n int, fn func(i int)) {
	var g errgroup.Group
	g.SetLimit(e.o.Concurrency)
	for i := range n {
		g.Go(func() error { fn(i); return nil })
	}
	g.Wait()
}

// meta returns deps.dev metadata per package version: fresh cache rows, else
// fetched (unless disabled) and cached. 404s are cached as empty rows.
func (e *Enricher) meta(ctx context.Context, items []item) map[metaKey]*pkgMeta {
	out := map[metaKey]*pkgMeta{}
	names := map[metaKey]string{} // original (un-normalized) name for the API
	var ecos, nns, vers []string
	for _, it := range items {
		k := metaKey{it.key, it.pkg.GetVersion()}
		if _, ok := depsDevSystems[k.eco]; !ok || names[k] != "" {
			continue
		}
		names[k] = it.pkg.GetName()
		ecos, nns, vers = append(ecos, k.eco), append(nns, k.name), append(vers, k.version)
	}
	if len(names) == 0 {
		return out
	}
	rows, err := e.pool.Query(ctx, `SELECT ecosystem, name_norm, version, licenses, coalesce(repo, ''), stars, forks
		FROM package_meta WHERE fetched_at > $4
		  AND (ecosystem, name_norm, version) IN (SELECT * FROM unnest($1::text[], $2::text[], $3::text[]))`,
		ecos, nns, vers, time.Now().Add(-e.o.CacheTTL))
	if err == nil {
		for rows.Next() {
			var k metaKey
			m := &pkgMeta{}
			if err = rows.Scan(&k.eco, &k.name, &k.version, &m.licenses, &m.repo, &m.stars, &m.forks); err != nil {
				break
			}
			out[k] = m
		}
		rows.Close()
		err = errors.Join(err, rows.Err())
	}
	if err != nil {
		e.o.Logger.Warn("enrich: package_meta cache read failed", "err", err)
	}
	if e.o.DisableDepsDev {
		return out
	}

	var miss []metaKey
	for k := range names {
		if out[k] == nil {
			miss = append(miss, k)
		}
	}
	fetched := make([]*pkgMeta, len(miss))
	e.parallel(len(miss), func(i int) {
		k := miss[i]
		var v struct {
			PublishedAt     string   `json:"publishedAt"`
			Licenses        []string `json:"licenses"`
			RelatedProjects []struct {
				ProjectKey struct {
					ID string `json:"id"`
				} `json:"projectKey"`
				RelationType string `json:"relationType"`
			} `json:"relatedProjects"`
		}
		u := fmt.Sprintf("%s/v3/systems/%s/packages/%s/versions/%s", e.o.DepsDevURL,
			depsDevSystems[k.eco], url.PathEscape(names[k]), url.PathEscape(k.version))
		err := e.getJSON(ctx, u, &v)
		if errors.Is(err, errNotFound) {
			fetched[i] = &pkgMeta{}
			return
		}
		if err != nil {
			e.o.Logger.Warn("enrich: deps.dev lookup failed", "pkg", names[k], "version", k.version, "err", err)
			return
		}
		m := &pkgMeta{licenses: v.Licenses}
		if t, err := time.Parse(time.RFC3339, v.PublishedAt); err == nil {
			m.published = &t
		}
		for _, p := range v.RelatedProjects { // prefer SOURCE_REPO, else any GitHub project
			if strings.HasPrefix(p.ProjectKey.ID, "github.com/") && (m.repo == "" || p.RelationType == "SOURCE_REPO") {
				m.repo = p.ProjectKey.ID
			}
		}
		fetched[i] = m
	})

	// Stars/forks once per repo.
	var repos []string
	repoIdx := map[string][]*pkgMeta{}
	for _, m := range fetched {
		if m != nil && m.repo != "" {
			if repoIdx[m.repo] == nil {
				repos = append(repos, m.repo)
			}
			repoIdx[m.repo] = append(repoIdx[m.repo], m)
		}
	}
	var mu sync.Mutex
	e.parallel(len(repos), func(i int) {
		var p struct {
			Stars int `json:"starsCount"`
			Forks int `json:"forksCount"`
		}
		if err := e.getJSON(ctx, e.o.DepsDevURL+"/v3/projects/"+url.PathEscape(repos[i]), &p); err != nil {
			e.o.Logger.Warn("enrich: deps.dev project lookup failed", "repo", repos[i], "err", err)
			return
		}
		mu.Lock()
		for _, m := range repoIdx[repos[i]] {
			m.stars, m.forks = &p.Stars, &p.Forks
		}
		mu.Unlock()
	})

	b := &pgx.Batch{}
	for i, m := range fetched {
		if m == nil {
			continue
		}
		k := miss[i]
		out[k] = m
		lic := m.licenses
		if lic == nil {
			lic = []string{}
		}
		b.Queue(`INSERT INTO package_meta (ecosystem, name_norm, version, licenses, repo, stars, forks, published_at, fetched_at)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7, $8, now())
			ON CONFLICT (ecosystem, name_norm, version) DO UPDATE SET licenses = EXCLUDED.licenses, repo = EXCLUDED.repo,
			  stars = EXCLUDED.stars, forks = EXCLUDED.forks, published_at = EXCLUDED.published_at, fetched_at = now()`,
			k.eco, k.name, k.version, lic, m.repo, m.stars, m.forks, m.published)
	}
	if b.Len() > 0 {
		if err := e.pool.SendBatch(ctx, b).Close(); err != nil {
			e.o.Logger.Warn("enrich: package_meta cache write failed", "err", err)
		}
	}
	return out
}

// scorecards returns OpenSSF Scorecard results per repo (github.com/org/repo),
// from cache or the Scorecard API. Repos without a scorecard map to nil.
func (e *Enricher) scorecards(ctx context.Context, repos []string) map[string]*insightapi.Scorecard {
	out := map[string]*insightapi.Scorecard{}
	sort.Strings(repos)
	repos = slices.Compact(repos)
	if len(repos) == 0 {
		return out
	}
	cached := map[string]bool{}
	rows, err := e.pool.Query(ctx, `SELECT repo, score, checks FROM scorecard WHERE fetched_at > $2 AND repo = ANY($1)`,
		repos, time.Now().Add(-e.o.CacheTTL))
	if err == nil {
		for rows.Next() {
			var repo string
			var score *float32
			var checks map[string]float32
			if err = rows.Scan(&repo, &score, &checks); err != nil {
				break
			}
			cached[repo] = true
			out[repo] = toScorecard(repo, score, checks)
		}
		rows.Close()
		err = errors.Join(err, rows.Err())
	}
	if err != nil {
		e.o.Logger.Warn("enrich: scorecard cache read failed", "err", err)
	}
	if e.o.DisableScorecard {
		return out
	}
	var miss []string
	for _, r := range repos {
		if !cached[r] {
			miss = append(miss, r)
		}
	}
	type result struct {
		ok     bool
		score  *float32
		checks map[string]float32
	}
	res := make([]result, len(miss))
	e.parallel(len(miss), func(i int) {
		var sc struct {
			Score  float32 `json:"score"`
			Checks []struct {
				Name  string  `json:"name"`
				Score float32 `json:"score"`
			} `json:"checks"`
		}
		segs := strings.Split(miss[i], "/")
		for j := range segs {
			segs[j] = url.PathEscape(segs[j])
		}
		err := e.getJSON(ctx, e.o.ScorecardURL+"/projects/"+strings.Join(segs, "/"), &sc)
		if errors.Is(err, errNotFound) {
			res[i] = result{ok: true, checks: map[string]float32{}}
			return
		}
		if err != nil {
			e.o.Logger.Warn("enrich: scorecard lookup failed", "repo", miss[i], "err", err)
			return
		}
		r := result{ok: true, score: &sc.Score, checks: map[string]float32{}}
		for _, c := range sc.Checks {
			r.checks[c.Name] = c.Score
		}
		res[i] = r
	})
	b := &pgx.Batch{}
	for i, r := range res {
		if !r.ok {
			continue
		}
		out[miss[i]] = toScorecard(miss[i], r.score, r.checks)
		b.Queue(`INSERT INTO scorecard (repo, score, checks, fetched_at) VALUES ($1, $2, $3, now())
			ON CONFLICT (repo) DO UPDATE SET score = EXCLUDED.score, checks = EXCLUDED.checks, fetched_at = now()`,
			miss[i], r.score, r.checks)
	}
	if b.Len() > 0 {
		if err := e.pool.SendBatch(ctx, b).Close(); err != nil {
			e.o.Logger.Warn("enrich: scorecard cache write failed", "err", err)
		}
	}
	return out
}

func toScorecard(repo string, score *float32, checks map[string]float32) *insightapi.Scorecard {
	if score == nil {
		return nil
	}
	names := make([]string, 0, len(checks))
	for n := range checks {
		names = append(names, n)
	}
	sort.Strings(names)
	cs := make([]insightapi.ScorecardV2Check, len(names))
	for i, n := range names {
		cs[i] = insightapi.ScorecardV2Check{Name: ptr(insightapi.ScorecardV2CheckName(n)), Score: ptr(checks[n])}
	}
	return &insightapi.Scorecard{Content: &insightapi.ScorecardContentV2{
		Score: score, Checks: &cs, Repository: &insightapi.ScorecardContentV2Repository{Name: ptr(repo)},
	}}
}
