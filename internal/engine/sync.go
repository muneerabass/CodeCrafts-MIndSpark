package engine

import (
	"context"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/ghapp"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/google/go-github/v92/github"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

type syncWorker struct {
	river.WorkerDefaults[jobs.SyncInstallation]
	d Deps
}

func (w *syncWorker) Timeout(*river.Job[jobs.SyncInstallation]) time.Duration { return 5 * time.Minute }

// Work reconciles gh_repositories with the installation's current repos.
func (w *syncWorker) Work(ctx context.Context, job *river.Job[jobs.SyncInstallation]) error {
	d, id := w.d, job.Args.InstallationID
	if d.Clients == nil {
		return river.JobCancel(errNoGitHub)
	}
	var status string
	if err := db.WithSystemTx(ctx, d.Pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM gh_installations WHERE id=$1`, id).Scan(&status)
	}); err != nil {
		return err
	}
	if status == "deleted" || status == "suspended" {
		return nil
	}
	gh, err := d.Clients.NewInstallationClient(id)
	if err != nil {
		return err
	}
	var repos []*github.Repository
	for r, err := range gh.Apps.ListReposIter(ctx, &github.ListOptions{PerPage: 100}) {
		if err != nil {
			return err
		}
		repos = append(repos, r)
	}
	return db.WithSystemTx(ctx, d.Pool, func(tx pgx.Tx) error {
		keep := make([]int64, 0, len(repos))
		for _, r := range repos {
			if err := ghapp.UpsertRepo(ctx, tx, id, r); err != nil {
				return err
			}
			keep = append(keep, r.GetID())
		}
		_, err := tx.Exec(ctx, `UPDATE gh_repositories SET removed_at=now()
			WHERE installation_id=$1 AND removed_at IS NULL AND NOT (id = ANY($2))`, id, keep)
		return err
	})
}
