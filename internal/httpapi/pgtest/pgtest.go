// Package pgtest starts a migrated Postgres in a container for integration
// tests and connects as the runtime roles (depguard_app, depguard_query).
package pgtest

import (
	"context"
	"net/url"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/httpapi/riverdb"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// DB is a migrated database with pools for each role.
type DB struct {
	OwnerDSN, AppDSN, QueryDSN string
	Owner, App, Query          *pgxpool.Pool
	stop                       func()
}

// Close stops pools and the container.
func (d *DB) Close() {
	for _, p := range []*pgxpool.Pool{d.Owner, d.App, d.Query} {
		if p != nil {
			p.Close()
		}
	}
	if d.stop != nil {
		d.stop()
	}
}

// Start runs postgres:17, applies goose + River migrations and sets role passwords.
func Start(ctx context.Context) (*DB, error) {
	ctr, err := postgres.Run(ctx, "postgres:17",
		postgres.WithDatabase("depguard"), postgres.WithUsername("depguard"), postgres.WithPassword("owner"),
		postgres.BasicWaitStrategies())
	d := &DB{}
	if ctr != nil {
		d.stop = func() { _ = testcontainers.TerminateContainer(ctr) }
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	if d.OwnerDSN, err = ctr.ConnectionString(ctx, "sslmode=disable"); err != nil {
		d.Close()
		return nil, err
	}
	if err := db.Migrate(ctx, d.OwnerDSN); err != nil {
		d.Close()
		return nil, err
	}
	if err := riverdb.Migrate(ctx, d.OwnerDSN); err != nil {
		d.Close()
		return nil, err
	}
	if d.Owner, err = db.Open(ctx, d.OwnerDSN); err != nil {
		d.Close()
		return nil, err
	}
	if _, err := d.Owner.Exec(ctx, `ALTER ROLE depguard_app PASSWORD 'app'; ALTER ROLE depguard_query PASSWORD 'query'`); err != nil {
		d.Close()
		return nil, err
	}
	d.AppDSN, d.QueryDSN = withUser(d.OwnerDSN, "depguard_app", "app"), withUser(d.OwnerDSN, "depguard_query", "query")
	if d.App, err = db.Open(ctx, d.AppDSN); err != nil {
		d.Close()
		return nil, err
	}
	if d.Query, err = db.Open(ctx, d.QueryDSN); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func withUser(dsn, user, pass string) string {
	u, _ := url.Parse(dsn)
	u.User = url.UserPassword(user, pass)
	return u.String()
}
