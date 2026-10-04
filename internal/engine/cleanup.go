package engine

import (
	"context"
	"time"

	"github.com/depguard/depguard/internal/jobs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// Retention windows for scan_uploads cleanup. Terminal (failed/skipped) scans
// keep their uploads briefly so an operator can inspect a failure; truly
// abandoned queued/running scans are purged after a longer grace period.
const (
	finishedUploadRetention  = time.Hour
	abandonedUploadRetention = 7 * 24 * time.Hour
	auditRetention           = 365 * 24 * time.Hour
)

type cleanupWorker struct {
	river.WorkerDefaults[jobs.CleanupScanUploads]
	pool *pgxpool.Pool
}

func (w *cleanupWorker) Timeout(*river.Job[jobs.CleanupScanUploads]) time.Duration {
	return 5 * time.Minute
}

// Work deletes scan_uploads rows whose scan has either finished (any status
// other than queued/running/success — success cleans up inline in persist) or
// has been queued/running past the abandoned-retention window. Scan metadata,
// reports, findings and package results are preserved.
//
// Runs as a system transaction (no app.tenant set) and bypasses RLS by using
// the owner connection via the River pool, which is the DATABASE_URL (depguard_app)
// role; scan_uploads RLS is tenant-scoped, so we scope the delete via a join
// against scans and iterate over tenants.
func (w *cleanupWorker) Work(ctx context.Context, _ *river.Job[jobs.CleanupScanUploads]) error {
	const sql = `
		WITH victims AS (
		  SELECT u.tenant_id, u.scan_id, u.path
		    FROM scan_uploads u
		    JOIN scans s ON s.id = u.scan_id
		   WHERE (s.status IN ('failed','skipped','cancelled')
		          AND s.finished_at IS NOT NULL
		          AND s.finished_at < now() - $1::interval)
		      OR (s.status IN ('queued','running')
		          AND s.created_at < now() - $2::interval)
		)
		DELETE FROM scan_uploads u
		 USING victims v
		 WHERE u.scan_id = v.scan_id AND u.path = v.path`
	// RLS scopes scan_uploads to app.tenant, so iterate over every tenant
	// (depguard_admin_tenants is the sanctioned cross-tenant list).
	rows, err := w.pool.Query(ctx, `SELECT tenant_id FROM depguard_admin_tenants()`)
	if err != nil {
		return err
	}
	tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, t := range tenants {
		if err := w.deleteOne(ctx, t, sql); err != nil {
			return err
		}
	}
	return nil
}

func (w *cleanupWorker) deleteOne(ctx context.Context, tenant, sql string) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant', $1, true)", tenant); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sql, finishedUploadRetention.String(), abandonedUploadRetention.String()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE created_at < now() - $1::interval`, auditRetention.String()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AddCleanupWorkers registers the scan_uploads cleanup worker.
func AddCleanupWorkers(w *river.Workers, pool *pgxpool.Pool) {
	river.AddWorker(w, &cleanupWorker{pool: pool})
}

// CleanupPeriodicJobs schedules scan_uploads cleanup every hour.
func CleanupPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{river.NewPeriodicJob(
		river.PeriodicInterval(time.Hour),
		func() (river.JobArgs, *river.InsertOpts) {
			return jobs.CleanupScanUploads{}, &river.InsertOpts{
				MaxAttempts: 3,
				UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
					rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
					rivertype.JobStateRetryable, rivertype.JobStateScheduled,
				}},
			}
		},
		&river.PeriodicJobOpts{ID: jobs.CleanupScanUploads{}.Kind(), RunOnStart: true},
	)}
}
