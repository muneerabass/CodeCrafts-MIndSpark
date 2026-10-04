package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/health"
	"github.com/jackc/pgx/v5"
)

type pkgFacts struct {
	ID, Ecosystem, Name, Version string
	Repo                         string
	Stars, Forks                 *int
	Published, LatestPublished   *time.Time
	FirstPublished               *time.Time
	DefaultVersion               *string
	Deprecated                   *bool
	DeprecatedReason             string
	Scorecard                    *float64
	ScorecardChecks              map[string]float64
	Malicious                    bool
	metaFound, latestFound       bool
}

// loadFacts reads cached deps.dev / Scorecard metadata for tenant components.
func loadFacts(ctx context.Context, tx pgx.Tx, ids []string) (map[string]*pkgFacts, error) {
	out := map[string]*pkgFacts{}
	rows, err := tx.Query(ctx, `SELECT c.id, c.ecosystem, c.name, c.version,
		EXISTS (SELECT 1 FROM component_vulnerabilities x WHERE x.component_id = c.id AND x.advisory_id LIKE 'MAL-%')
		 OR COALESCE((SELECT a.status FROM package_analyses a WHERE a.component_id = c.id ORDER BY a.created_at DESC LIMIT 1) = 'malicious', false)
		FROM components c WHERE c.id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	var ecos, names, vers []string
	key := map[[3]string][]*pkgFacts{}
	for rows.Next() {
		f := &pkgFacts{}
		if err := rows.Scan(&f.ID, &f.Ecosystem, &f.Name, &f.Version, &f.Malicious); err != nil {
			rows.Close()
			return nil, err
		}
		out[f.ID] = f
		eco := enrich.OSVEcosystemName(f.Ecosystem)
		if eco == "" {
			continue
		}
		k := [3]string{eco, feeds.NormalizeName(eco, f.Name), f.Version}
		key[k] = append(key[k], f)
		ecos, names, vers = append(ecos, k[0]), append(names, k[1]), append(vers, k[2])
	}
	rows.Close()
	if len(ecos) == 0 {
		return out, nil
	}
	rows, err = tx.Query(ctx, `SELECT ecosystem, name_norm, version, COALESCE(repo, ''), stars, forks, published_at FROM package_meta
		WHERE (ecosystem, name_norm, version) IN (SELECT * FROM unnest($1::text[], $2::text[], $3::text[]))`, ecos, names, vers)
	if err != nil {
		return nil, err
	}
	repos := map[string][]*pkgFacts{}
	for rows.Next() {
		var k [3]string
		var repo string
		var stars, forks *int
		var pub *time.Time
		if err := rows.Scan(&k[0], &k[1], &k[2], &repo, &stars, &forks, &pub); err != nil {
			rows.Close()
			return nil, err
		}
		for _, f := range key[k] {
			f.Repo, f.Stars, f.Forks, f.Published, f.metaFound = repo, stars, forks, pub, true
			if repo != "" {
				repos[repo] = append(repos[repo], f)
			}
		}
	}
	rows.Close()
	rows, err = tx.Query(ctx, `SELECT ecosystem, name_norm, default_version, latest_published, first_published, deprecated, COALESCE(deprecated_reason, '')
		FROM package_latest WHERE found AND (ecosystem, name_norm) IN (SELECT * FROM unnest($1::text[], $2::text[]))`, ecos, names)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var eco, nn, reason string
		var def *string
		var latest, first *time.Time
		var dep bool
		if err := rows.Scan(&eco, &nn, &def, &latest, &first, &dep, &reason); err != nil {
			rows.Close()
			return nil, err
		}
		for k, fs := range key {
			if k[0] == eco && k[1] == nn {
				for _, f := range fs {
					d := dep
					f.DefaultVersion, f.LatestPublished, f.FirstPublished, f.Deprecated, f.DeprecatedReason, f.latestFound = def, latest, first, &d, reason, true
				}
			}
		}
	}
	rows.Close()
	if len(repos) == 0 {
		return out, nil
	}
	rl := make([]string, 0, len(repos))
	for r := range repos {
		rl = append(rl, r)
	}
	rows, err = tx.Query(ctx, `SELECT repo, score, checks FROM scorecard WHERE repo = ANY($1) AND score IS NOT NULL`, rl)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var repo string
		var score float64
		var checks []byte
		if err := rows.Scan(&repo, &score, &checks); err != nil {
			return nil, err
		}
		var cm map[string]float64
		_ = json.Unmarshal(checks, &cm)
		for _, f := range repos[repo] {
			s := score
			f.Scorecard, f.ScorecardChecks = &s, cm
		}
	}
	return out, rows.Err()
}

func (f *pkgFacts) health() health.Result {
	in := health.Input{Scorecard: f.Scorecard, LastRelease: f.LatestPublished, FirstPublished: f.FirstPublished, Stars: f.Stars,
		Deprecated: f.Deprecated, Malicious: f.Malicious, Now: time.Now()}
	if f.metaFound {
		has := f.Repo != ""
		in.HasRepo = &has
	}
	if in.LastRelease == nil {
		in.LastRelease = f.Published
	}
	return health.Score(in)
}

// componentsHealth scores up to 50 components: GET /components/health?ids=a,b
func (s *Server) componentsHealth(w http.ResponseWriter, r *http.Request) error {
	ids := strings.Split(r.URL.Query().Get("ids"), ",")
	if len(ids) > 50 {
		return badRequest("at most 50 ids")
	}
	out := map[string]health.Result{}
	err := s.tx(r, func(tx pgx.Tx) error {
		facts, err := loadFacts(r.Context(), tx, ids)
		for id, f := range facts {
			out[id] = f.health()
		}
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// getComponent is the package detail page: metadata, health, vulnerabilities and where it is used.
func (s *Server) getComponent(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	var out map[string]any
	err := s.tx(r, func(tx pgx.Tx) error {
		var base json.RawMessage
		if err := tx.QueryRow(r.Context(), `SELECT jsonb_build_object('id', c.id, 'name', c.name, 'version', c.version, 'ecosystem', c.ecosystem,
			'purl', c.purl, 'licenses', COALESCE(c.licenses, '{}'),
			'vulns', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', x.advisory_id, 'risk', x.risk, 'fixed_in', x.fixed_in, 'summary', a.summary)
				ORDER BY array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW'], x.risk), x.advisory_id)
				FROM component_vulnerabilities x LEFT JOIN advisory a ON a.id = x.advisory_id WHERE x.component_id = c.id), '[]'::jsonb),
			'projects', COALESCE((SELECT jsonb_agg(DISTINCT jsonb_build_object('id', p.id, 'name', p.name, 'version', v.name, 'version_id', v.id,
				'manifest_path', pvc.manifest_path, 'direct', pvc.direct))
				FROM project_version_components pvc JOIN project_versions v ON v.id = pvc.project_version_id JOIN projects p ON p.id = v.project_id
				WHERE pvc.component_id = c.id), '[]'::jsonb),
			'analysis', (SELECT jsonb_build_object('id', a.id, 'status', a.status, 'verified', a.verified) FROM package_analyses a
				WHERE a.component_id = c.id ORDER BY a.created_at DESC LIMIT 1))
			FROM components c WHERE c.id = $1`, id).Scan(&base); err != nil {
			return err
		}
		if err := json.Unmarshal(base, &out); err != nil {
			return err
		}
		facts, err := loadFacts(r.Context(), tx, []string{id})
		if err != nil {
			return err
		}
		f := facts[id]
		out["health"] = f.health()
		out["meta"] = map[string]any{"repo": f.Repo, "stars": f.Stars, "forks": f.Forks, "published_at": f.Published,
			"latest_published": f.LatestPublished, "first_published": f.FirstPublished, "default_version": f.DefaultVersion,
			"deprecated": f.Deprecated, "deprecated_reason": f.DeprecatedReason}
		out["scorecard"] = map[string]any{"score": f.Scorecard, "checks": f.ScorecardChecks}
		return nil
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}
