// Package db opens Postgres pools, runs migrations and scopes transactions to a tenant.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/depguard/depguard/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for goose
	"github.com/pressly/goose/v3"
)

// Open connects a pool. Use the depguard_app role at runtime so RLS applies.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// Migrate applies embedded migrations. ownerDSN must be the schema owner role.
func Migrate(ctx context.Context, ownerDSN string) error {
	sqlDB, err := sql.Open("pgx", ownerDSN)
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.UpContext(ctx, sqlDB, ".")
}

// ErrNoTenant guards against running tenant queries without a tenant.
var ErrNoTenant = errors.New("db: empty tenant id")

// RejectSupabaseDSN returns an error when dsn points at Supabase. Application
// data (scans, uploads, queues, orgs, memberships, settings) lives in local
// PostgreSQL; Supabase is used only for Auth. Call this for every DATABASE_URL*.
func RejectSupabaseDSN(name, dsn string) error {
	if dsn == "" {
		return nil
	}
	lower := strings.ToLower(dsn)
	if strings.Contains(lower, "pooler.supabase.com") || strings.Contains(lower, ".supabase.co") {
		return fmt.Errorf("%s must point at local PostgreSQL; Supabase is only for Auth (got a Supabase host)", name)
	}
	return nil
}

// WithTenantTx runs fn in a transaction where RLS sees only tenantID's rows.
// This is the only sanctioned way to touch tenant tables.
func WithTenantTx(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant', $1, true)", tenantID); err != nil {
			return fmt.Errorf("set tenant: %w", err)
		}
		return fn(tx)
	})
}

// WithSystemTx runs fn without a tenant: only global tables (feeds, GitHub
// installations, webhook deliveries) are visible.
func WithSystemTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, pool, fn)
}
