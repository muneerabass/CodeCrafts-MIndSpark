// Package riverdb runs River's schema migrations and builds the insert-only
// River client the API uses to enqueue jobs.
package riverdb

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

// Migrate applies River migrations as the schema owner, then grants the
// runtime role access to River's tables (they are created by River, not goose).
func Migrate(ctx context.Context, ownerDSN string) error {
	pool, err := pgxpool.New(ctx, ownerDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	m, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return err
	}
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("river migrate: %w", err)
	}
	_, err = pool.Exec(ctx, `DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE 'river\_%' LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO depguard_app', t);
  END LOOP;
  GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO depguard_app;
END $$`)
	if err != nil {
		return fmt.Errorf("grant river tables: %w", err)
	}
	return nil
}

// NewInserter returns a River client that only inserts jobs (no workers).
func NewInserter(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
	return river.NewClient(riverpgxv5.New(pool), &river.Config{})
}
