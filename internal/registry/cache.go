package registry

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"
)

// Supported reports whether releases of an OSV ecosystem can be read.
func Supported(eco string) bool { return eco == "npm" || eco == "PyPI" }

// Pkg identifies a package: Name as published (for the registry URL), Norm as stored.
type Pkg struct{ Eco, Name, Norm string }

// Cached returns releases per package from registry_versions, fetching
// packages whose cache is stale (1h while the newest release is under a week
// old, else 24h). Packages that cannot be read are absent: callers skip rules.
func (c *Client) Cached(ctx context.Context, pool *pgxpool.Pool, pkgs []Pkg) map[Pkg][]Version {
	out := map[Pkg][]Version{}
	var stale []Pkg
	for _, p := range pkgs {
		if !Supported(p.Eco) {
			continue
		}
		vs, fresh, err := load(ctx, pool, p)
		if err != nil {
			continue
		}
		if fresh {
			if vs != nil {
				out[p] = vs
			}
			continue
		}
		stale = append(stale, p)
	}
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(4) // ponytail: fixed fan-out, make configurable if registries rate-limit
	for _, p := range stale {
		g.Go(func() error {
			fetch := c.NPM
			if p.Eco == "PyPI" {
				fetch = c.PyPI
			}
			vs, err := fetch(gctx, p.Name)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return nil // network trouble: rules stay off for this package
			}
			if store(context.WithoutCancel(ctx), pool, p, vs) == nil && vs != nil {
				mu.Lock()
				out[p] = vs
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()
	return out
}

func load(ctx context.Context, pool *pgxpool.Pool, p Pkg) ([]Version, bool, error) {
	var found bool
	var newest *time.Time
	var at time.Time
	err := pool.QueryRow(ctx, `SELECT found, newest, fetched_at FROM registry_fetched WHERE ecosystem=$1 AND name_norm=$2`, p.Eco, p.Norm).Scan(&found, &newest, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	ttl := 24 * time.Hour
	if newest != nil && time.Since(*newest) < 7*24*time.Hour {
		ttl = time.Hour
	}
	if time.Since(at) > ttl {
		return nil, false, nil
	}
	if !found {
		return nil, true, nil
	}
	rows, err := pool.Query(ctx, `SELECT version, published_at, publisher, provenance, install_scripts FROM registry_versions
		WHERE ecosystem=$1 AND name_norm=$2 ORDER BY published_at`, p.Eco, p.Norm)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var vs []Version
	for rows.Next() {
		var v Version
		var scripts []byte
		if err := rows.Scan(&v.Version, &v.Published, &v.Publisher, &v.Provenance, &scripts); err != nil {
			return nil, false, err
		}
		_ = json.Unmarshal(scripts, &v.Scripts)
		if len(v.Scripts) == 0 {
			v.Scripts = nil
		}
		vs = append(vs, v)
	}
	return vs, true, rows.Err()
}

func store(ctx context.Context, pool *pgxpool.Pool, p Pkg, vs []Version) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var newest *time.Time
	if len(vs) > 0 {
		newest = &vs[len(vs)-1].Published
	}
	if _, err := tx.Exec(ctx, `DELETE FROM registry_versions WHERE ecosystem=$1 AND name_norm=$2`, p.Eco, p.Norm); err != nil {
		return err
	}
	b := &pgx.Batch{}
	for _, v := range vs {
		s, _ := json.Marshal(v.Scripts)
		if v.Scripts == nil {
			s = []byte("{}")
		}
		b.Queue(`INSERT INTO registry_versions (ecosystem, name_norm, version, published_at, publisher, provenance, install_scripts)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, p.Eco, p.Norm, v.Version, v.Published, v.Publisher, v.Provenance, s)
	}
	b.Queue(`INSERT INTO registry_fetched (ecosystem, name_norm, found, newest, fetched_at) VALUES ($1,$2,$3,$4,now())
		ON CONFLICT (ecosystem, name_norm) DO UPDATE SET found=EXCLUDED.found, newest=EXCLUDED.newest, fetched_at=now()`,
		p.Eco, p.Norm, vs != nil, newest)
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
