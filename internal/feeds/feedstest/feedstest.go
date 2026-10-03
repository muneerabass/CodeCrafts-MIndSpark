// Package feedstest starts a throwaway Postgres for tests: migrated with the
// owner role, then connected as depguard_app so real grants apply.
package feedstest

import (
	"context"
	"net/url"
	"testing"

	"github.com/depguard/depguard/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// Postgres returns a depguard_app pool on a fresh migrated database. The
// container is removed when the test ends. Skips if Docker is unavailable.
func Postgres(t testing.TB) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	ctr, err := postgres.Run(ctx, "postgres:18-alpine",
		postgres.WithDatabase("depguard"), postgres.WithUsername("depguard"), postgres.WithPassword("owner"),
		postgres.BasicWaitStrategies())
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Skipf("postgres container unavailable: %v", err)
	}
	ownerDSN, err := ctr.ConnectionString(ctx, "sslmode=disable")
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
	_, err = owner.Exec(ctx, `ALTER ROLE depguard_app PASSWORD 'x'`)
	owner.Close()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(ownerDSN)
	u.User = url.UserPassword("depguard_app", "x")
	pool, err := db.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}
