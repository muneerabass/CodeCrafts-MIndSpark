// Package testpg starts a migrated Postgres (domain schema + River) for tests
// and connects as depguard_app so RLS is exercised.
package testpg

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// DB holds the runtime (RLS) pool and a superuser pool for seeding/asserting.
type DB struct {
	App, Owner *pgxpool.Pool
}

// Start skips the test when Docker is unavailable.
func Start(t testing.TB) DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("depguard"), postgres.WithUsername("depguard"), postgres.WithPassword("owner"),
		postgres.BasicWaitStrategies())
	if err != nil {
		t.Skipf("postgres container unavailable: %v", err)
	}
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(c) })
	ownerDSN, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, ownerDSN); err != nil {
		t.Fatal(err)
	}
	owner, err := db.Open(ctx, ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	m, err := rivermigrate.New(riverpgxv5.New(owner), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		t.Fatal(err)
	}
	_, err = owner.Exec(ctx, `ALTER ROLE depguard_app PASSWORD 'app';
		DO $$ DECLARE t text; BEGIN
		  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'river%' LOOP
		    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO depguard_app', t);
		  END LOOP;
		END $$;
		GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO depguard_app;`)
	if err != nil {
		t.Fatal(err)
	}
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	app, err := db.Open(ctx, fmt.Sprintf("postgres://depguard_app:app@%s:%s/depguard?sslmode=disable", host, port.Port()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	return DB{App: app, Owner: owner}
}
