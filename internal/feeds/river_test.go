package feeds

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// TestRiverConfig checks River accepts our workers and periodic jobs (no DB needed).
func TestRiverConfig(t *testing.T) {
	w := river.NewWorkers()
	AddWorkers(w, (*pgxpool.Pool)(nil))
	pool, err := pgxpool.New(context.Background(), "postgres://unused@127.0.0.1:1/x")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:       map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 1}},
		Workers:      w,
		PeriodicJobs: PeriodicJobs(),
	})
	if err != nil {
		t.Fatal(err)
	}
}
