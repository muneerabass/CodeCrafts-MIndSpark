package enrich

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/depguard/depguard/internal/feeds"
	"github.com/jackc/pgx/v5"
	"github.com/safedep/vet/pkg/models"
)

// Latest is package-level maintenance data from deps.dev GetPackage, cached
// in package_latest.
type Latest struct {
	Found              bool       // false: deps.dev doesn't know the package
	DefaultVersion     string     // the version deps.dev marks isDefault (usually latest stable)
	LatestPublished    *time.Time // newest publishedAt over all versions; nil if unknown
	Deprecated         bool       // the default version is deprecated
	DeprecatedVersions []string   // every deprecated version
	DeprecatedReason   string     // deprecation message of the default version
}

// VersionDeprecated reports whether version (or the whole package) is deprecated.
func (l *Latest) VersionDeprecated(version string) bool {
	return l != nil && (l.Deprecated || slices.Contains(l.DeprecatedVersions, version))
}

// PackageLatest returns maintenance data for one package (eco is an OSV
// ecosystem). It returns (nil, nil) when unsupported, or when deps.dev is
// disabled and nothing is cached; network errors are returned.
func (e *Enricher) PackageLatest(ctx context.Context, eco, name string) (*Latest, error) {
	k := key{eco, feeds.NormalizeName(eco, name)}
	out, err := e.latest(ctx, map[key]string{k: name})
	return out[k], err
}

// PackagesLatest is PackageLatest for many packages (one lookup per distinct
// package name). Packages without data are absent; network errors are logged.
func (e *Enricher) PackagesLatest(ctx context.Context, pkgs []*models.Package) map[*models.Package]*Latest {
	names := map[key]string{}
	for _, p := range pkgs {
		if eco := OSVEcosystem(p); eco != "" {
			if k := (key{eco, feeds.NormalizeName(eco, p.GetName())}); names[k] == "" {
				names[k] = p.GetName()
			}
		}
	}
	got, err := e.latest(ctx, names)
	if err != nil {
		e.o.Logger.Warn("enrich: deps.dev package lookups failed", "err", err)
	}
	out := map[*models.Package]*Latest{}
	for _, p := range pkgs {
		eco := OSVEcosystem(p)
		if l := got[key{eco, feeds.NormalizeName(eco, p.GetName())}]; l != nil {
			out[p] = l
		}
	}
	return out
}

// latest serves fresh package_latest rows, fetching (unless disabled) and
// caching the rest. 404s are cached as found=false.
func (e *Enricher) latest(ctx context.Context, names map[key]string) (map[key]*Latest, error) {
	out := map[key]*Latest{}
	var ecos, nns []string
	for k := range names {
		if _, ok := depsDevSystems[k.eco]; ok {
			ecos, nns = append(ecos, k.eco), append(nns, k.name)
		}
	}
	if len(ecos) == 0 {
		return out, nil
	}
	rows, err := e.pool.Query(ctx, `SELECT ecosystem, name_norm, found, coalesce(default_version, ''), latest_published,
		  deprecated, deprecated_versions, coalesce(deprecated_reason, '')
		FROM package_latest WHERE fetched_at > $3
		  AND (ecosystem, name_norm) IN (SELECT * FROM unnest($1::text[], $2::text[]))`,
		ecos, nns, time.Now().Add(-e.o.CacheTTL))
	if err == nil {
		for rows.Next() {
			var k key
			l := &Latest{}
			if err = rows.Scan(&k.eco, &k.name, &l.Found, &l.DefaultVersion, &l.LatestPublished,
				&l.Deprecated, &l.DeprecatedVersions, &l.DeprecatedReason); err != nil {
				break
			}
			out[k] = l
		}
		rows.Close()
		err = errors.Join(err, rows.Err())
	}
	if err != nil {
		e.o.Logger.Warn("enrich: package_latest cache read failed", "err", err)
	}
	if e.o.DisableDepsDev {
		return out, nil
	}

	var miss []key
	for i := range ecos {
		if k := (key{ecos[i], nns[i]}); out[k] == nil {
			miss = append(miss, k)
		}
	}
	fetched := make([]*Latest, len(miss))
	errs := make([]error, len(miss))
	e.parallel(len(miss), func(i int) {
		fetched[i], errs[i] = e.fetchLatest(ctx, miss[i].eco, names[miss[i]])
	})

	b := &pgx.Batch{}
	for i, l := range fetched {
		if l == nil {
			continue
		}
		k := miss[i]
		out[k] = l
		dv := l.DeprecatedVersions
		if dv == nil {
			dv = []string{}
		}
		b.Queue(`INSERT INTO package_latest (ecosystem, name_norm, default_version, latest_published, deprecated,
			  deprecated_versions, deprecated_reason, found, fetched_at)
			VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, NULLIF($7, ''), $8, now())
			ON CONFLICT (ecosystem, name_norm) DO UPDATE SET default_version = EXCLUDED.default_version,
			  latest_published = EXCLUDED.latest_published, deprecated = EXCLUDED.deprecated,
			  deprecated_versions = EXCLUDED.deprecated_versions, deprecated_reason = EXCLUDED.deprecated_reason,
			  found = EXCLUDED.found, fetched_at = now()`,
			k.eco, k.name, l.DefaultVersion, l.LatestPublished, l.Deprecated, dv, l.DeprecatedReason, l.Found)
	}
	if b.Len() > 0 {
		if err := e.pool.SendBatch(ctx, b).Close(); err != nil {
			e.o.Logger.Warn("enrich: package_latest cache write failed", "err", err)
		}
	}
	return out, errors.Join(errs...)
}

// fetchLatest calls GET /v3/systems/{s}/packages/{name}, plus GetVersion of
// the default version for its deprecation reason when it is deprecated.
func (e *Enricher) fetchLatest(ctx context.Context, eco, name string) (*Latest, error) {
	sys := depsDevSystems[eco]
	var v struct {
		Versions []struct {
			VersionKey struct {
				Version string `json:"version"`
			} `json:"versionKey"`
			PublishedAt  string `json:"publishedAt"`
			IsDefault    bool   `json:"isDefault"`
			IsDeprecated bool   `json:"isDeprecated"`
		} `json:"versions"`
	}
	u := fmt.Sprintf("%s/v3/systems/%s/packages/%s", e.o.DepsDevURL, sys, url.PathEscape(name))
	if err := e.getJSON(ctx, u, &v); errors.Is(err, errNotFound) {
		return &Latest{}, nil
	} else if err != nil {
		return nil, fmt.Errorf("deps.dev package %s: %w", name, err)
	}
	l := &Latest{Found: true}
	for _, ver := range v.Versions {
		if t, err := time.Parse(time.RFC3339, ver.PublishedAt); err == nil && (l.LatestPublished == nil || t.After(*l.LatestPublished)) {
			l.LatestPublished = &t
		}
		if ver.IsDeprecated {
			l.DeprecatedVersions = append(l.DeprecatedVersions, ver.VersionKey.Version)
		}
		if ver.IsDefault {
			l.DefaultVersion, l.Deprecated = ver.VersionKey.Version, ver.IsDeprecated
		}
	}
	if l.Deprecated {
		var gv struct {
			DeprecatedReason string `json:"deprecatedReason"`
		}
		u := fmt.Sprintf("%s/v3/systems/%s/packages/%s/versions/%s", e.o.DepsDevURL, sys,
			url.PathEscape(name), url.PathEscape(l.DefaultVersion))
		if err := e.getJSON(ctx, u, &gv); err != nil {
			e.o.Logger.Warn("enrich: deps.dev deprecation reason lookup failed", "pkg", name, "err", err)
		}
		l.DeprecatedReason = gv.DeprecatedReason
	}
	return l, nil
}
