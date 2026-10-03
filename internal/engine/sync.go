package engine

import (
	"context"
	"strings"
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
	if err := db.WithSystemTx(ctx, d.Pool, func(tx pgx.Tx) error {
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
	}); err != nil {
		return err
	}
	tenant, err := installationTenant(ctx, d.Pool, id)
	if err != nil || tenant == "" {
		return err
	}
	for _, r := range repos {
		if err := d.syncPullRequests(ctx, gh, tenant, id, r); err != nil {
			d.Logger.Warn("sync pull requests", "repo", r.GetFullName(), "err", err)
		}
	}
	return nil
}

const maxBackfillPRs = 50

// syncPullRequests imports the repository's open pull requests, queues a scan
// for each one whose head has not been scanned, and marks PRs closed or
// merged on GitHub (missed webhooks).
func (d Deps) syncPullRequests(ctx context.Context, gh *github.Client, tenant string, installationID int64, repo *github.Repository) error {
	owner, name, _ := strings.Cut(repo.GetFullName(), "/")
	var open []*github.PullRequest
	for pr, err := range gh.PullRequests.ListIter(ctx, owner, name, &github.PullRequestListOptions{State: "open", Sort: "updated", Direction: "desc",
		ListOptions: github.ListOptions{PerPage: 50}}) {
		if err != nil {
			return err
		}
		open = append(open, pr)
		if len(open) == maxBackfillPRs {
			break
		}
	}
	var toScan []*github.PullRequest
	var stale []int
	err := withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		var scanDrafts bool
		_ = tx.QueryRow(ctx, `SELECT scan_draft_prs FROM tenant_settings`).Scan(&scanDrafts)
		seen := make([]int, 0, len(open))
		for _, pr := range open {
			seen = append(seen, pr.GetNumber())
			prID, err := ghapp.UpsertPR(ctx, tx, tenant, installationID, repo, pr)
			if err != nil {
				return err
			}
			var scanned bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pull_requests p JOIN scans s ON s.id = p.latest_scan_id
				WHERE p.id=$1 AND s.head_sha=$2 AND s.status IN ('success','running','queued'))`, prID, pr.GetHead().GetSHA()).Scan(&scanned); err != nil {
				return err
			}
			if !scanned && (!pr.GetDraft() || scanDrafts) {
				toScan = append(toScan, pr)
			}
		}
		rows, err := tx.Query(ctx, `SELECT number FROM pull_requests WHERE repo_id=$1 AND state='open' AND NOT (number = ANY($2))`, repo.GetID(), seen)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n int
			if err := rows.Scan(&n); err == nil {
				stale = append(stale, n)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, n := range stale {
		if len(open) == maxBackfillPRs {
			break // the list was capped: absence does not mean closed
		}
		pr, _, err := gh.PullRequests.Get(ctx, owner, name, n)
		if err != nil {
			continue
		}
		_ = withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
			_, err := ghapp.UpsertPR(ctx, tx, tenant, installationID, repo, pr)
			return err
		})
	}
	for _, pr := range toScan {
		if err := d.enqueuePRScan(ctx, installationID, repo.GetID(), repo.GetFullName(), pr); err != nil {
			return err
		}
	}
	d.Logger.Info("pull requests synced", "repo", repo.GetFullName(), "open", len(open), "queued", len(toScan), "closed", len(stale))
	return nil
}

type syncAllWorker struct {
	river.WorkerDefaults[jobs.SyncAllInstallations]
	d Deps
}

func (w *syncAllWorker) Work(ctx context.Context, _ *river.Job[jobs.SyncAllInstallations]) error {
	var ids []int64
	if err := db.WithSystemTx(ctx, w.d.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM gh_installations WHERE status='linked' AND tenant_id IS NOT NULL`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}); err != nil {
		return err
	}
	for _, id := range ids {
		if err := w.d.enqueue(ctx, jobs.SyncInstallation{InstallationID: id}, &river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true}}); err != nil {
			return err
		}
	}
	return nil
}

// PeriodicJobs are the engine's scheduled jobs.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(6*time.Hour),
		func() (river.JobArgs, *river.InsertOpts) { return jobs.SyncAllInstallations{}, nil },
		&river.PeriodicJobOpts{ID: "sync_all_installations", RunOnStart: true})}
}
