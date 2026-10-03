package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/render"
	"github.com/depguard/depguard/internal/scan"
	"github.com/google/go-github/v92/github"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

type prWorker struct {
	river.WorkerDefaults[jobs.ScanPullRequest]
	d Deps
}

func (w *prWorker) Timeout(*river.Job[jobs.ScanPullRequest]) time.Duration { return 15 * time.Minute }

func withTenant(ctx context.Context, d Deps, tenant string, fn func(pgx.Tx) error) error {
	return db.WithTenantTx(context.WithoutCancel(ctx), d.Pool, tenant, fn)
}

// prScan is the state of one PR scan attempt.
type prScan struct {
	a                            jobs.ScanPullRequest
	owner, repo                  string
	tenant, projectID, versionID string
	scanID                       string
	checkRunID, prevCommentID    int64
	settings                     settings
	gh                           *github.Client
}

func (w *prWorker) Work(ctx context.Context, job *river.Job[jobs.ScanPullRequest]) error {
	d, a := w.d, job.Args
	log := d.Logger.With("job", job.ID, "repo", a.RepoFullName, "pr", a.PRNumber, "head", a.HeadSHA)
	if d.Clients == nil {
		return river.JobCancel(errNoGitHub)
	}
	tenant, err := installationTenant(ctx, d.Pool, a.InstallationID)
	if err != nil {
		return err
	}
	if tenant == "" {
		log.Info("installation not linked, skipping")
		return nil
	}
	owner, repo, ok := strings.Cut(a.RepoFullName, "/")
	if !ok {
		return river.JobCancel(fmt.Errorf("bad repo name %q", a.RepoFullName))
	}
	gh, err := d.Clients.NewInstallationClient(a.InstallationID)
	if err != nil {
		return err
	}
	s := &prScan{a: a, owner: owner, repo: repo, tenant: tenant, gh: gh}

	done := false
	err = withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		if s.settings, err = loadSettings(ctx, tx); err != nil {
			return err
		}
		if s.settings.Disabled {
			done = true
			return nil
		}
		if s.projectID, err = ensureProject(ctx, tx, tenant, "github", a.RepoFullName, "https://github.com/"+a.RepoFullName, a.RepoID); err != nil {
			return err
		}
		if s.versionID, err = ensureVersion(ctx, tx, tenant, s.projectID, a.BaseRef); err != nil {
			return err
		}
		// Idempotent per (repo, pr, head_sha): reuse the row of an earlier attempt.
		var status string
		var cr *int64
		err := tx.QueryRow(ctx, `SELECT id, status, check_run_id FROM scans WHERE project_id=$1 AND pr_number=$2 AND head_sha=$3
			AND trigger='pull_request' ORDER BY created_at DESC LIMIT 1`, s.projectID, a.PRNumber, a.HeadSHA).Scan(&s.scanID, &status, &cr)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			s.scanID = ids.New()
			_, err = tx.Exec(ctx, `INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status, pr_number, head_sha, base_sha, started_at)
				VALUES ($1,$2,$3,$4,'pull_request','running',$5,$6,$7,now())`, s.scanID, tenant, s.projectID, s.versionID, a.PRNumber, a.HeadSHA, a.BaseSHA)
			if err != nil {
				return err
			}
		case err != nil:
			return err
		// A finished scan is only redone on an explicit re-run (new job after completion).
		case (status == "success" || status == "skipped") && job.Attempt > 1:
			done = true
			return nil
		default:
			if cr != nil && job.Attempt > 1 { // a re-run gets a fresh check run
				s.checkRunID = *cr
			}
			if err := startScan(ctx, tx, s.scanID); err != nil {
				return err
			}
		}
		err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT comment_id FROM scans WHERE project_id=$1 AND pr_number=$2 AND comment_id IS NOT NULL
			ORDER BY created_at DESC LIMIT 1), 0)`, s.projectID, a.PRNumber).Scan(&s.prevCommentID)
		return err
	})
	if err != nil || done {
		return err
	}

	if s.checkRunID == 0 {
		if s.checkRunID, err = d.createCheckRun(ctx, gh, owner, repo, a.HeadSHA, s.scanID); err != nil {
			d.finishScan(ctx, tenant, s.scanID, "failed", err)
			return fmt.Errorf("create check run: %w", err)
		}
		if err := withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE scans SET check_run_id=$2 WHERE id=$1`, s.scanID, s.checkRunID)
			return err
		}); err != nil {
			return err
		}
	}

	if err := w.run(ctx, s); err != nil {
		log.Error("pr scan failed", "attempt", job.Attempt, "err", err)
		d.finishScan(ctx, tenant, s.scanID, "failed", err)
		if job.Attempt >= job.MaxAttempts {
			_ = d.completeCheckRun(ctx, gh, owner, repo, s.checkRunID, "neutral", "depguard could not complete the scan",
				"The scan failed after several attempts. Re-run the check to try again.", nil)
		}
		return err
	}
	return nil
}

func (w *prWorker) run(ctx context.Context, s *prScan) error {
	d, a, gh := w.d, s.a, s.gh
	start := time.Now()
	files, mergeBase, err := changedFiles(ctx, gh, s.owner, s.repo, a.PRNumber, a.BaseSHA, a.HeadSHA)
	if err != nil {
		return fmt.Errorf("list PR files: %w", err)
	}

	// Fetch base and head versions of changed manifests.
	var baseFiles, headFiles []file
	var notes []string
	n := 0
	for _, f := range files {
		if !scan.IsManifest(f.Path) && !(f.PrevPath != "" && scan.IsManifest(f.PrevPath)) {
			continue
		}
		if n++; n > maxManifests {
			notes = append(notes, fmt.Sprintf("only the first %d manifests were scanned", maxManifests))
			break
		}
		if f.Status != "removed" && scan.IsManifest(f.Path) {
			b, err := fetchBlob(ctx, gh, s.owner, s.repo, f.SHA, maxManifestBytes)
			if errors.Is(err, errTooLarge) {
				notes = append(notes, "skipped oversized "+f.Path)
				continue
			} else if err != nil {
				return fmt.Errorf("fetch %s: %w", f.Path, err)
			}
			headFiles = append(headFiles, file{Path: f.Path, Data: b})
		}
		if f.Status != "added" {
			basePath := f.Path
			if f.PrevPath != "" {
				basePath = f.PrevPath
			}
			b, err := fileAt(ctx, gh, s.owner, s.repo, basePath, mergeBase, maxManifestBytes)
			if err != nil && !errors.Is(err, errTooLarge) {
				return fmt.Errorf("fetch base %s: %w", basePath, err)
			}
			if b != nil {
				// Compare under the head path so renames diff against their old content.
				baseFiles = append(baseFiles, file{Path: f.Path, Data: b})
			}
		}
	}
	noChanges := len(headFiles) == 0 && len(baseFiles) == 0

	var findings []*finding
	if !noChanges {
		base, _, err := parseFiles(baseFiles)
		if err != nil {
			return err
		}
		head, n2, err := parseFiles(headFiles)
		if err != nil {
			return err
		}
		notes = append(notes, n2...)
		if findings, err = d.evaluate(ctx, scan.Diff(base, head), s.settings); err != nil {
			return err
		}
	}

	var ai []string
	if !d.DisableXBOM {
		ai = aiUsage(sourceFiles(ctx, gh, s.owner, s.repo, files), d.Logger)
	}

	// Drop results if the PR moved on while we were scanning.
	pr, _, err := gh.PullRequests.Get(ctx, s.owner, s.repo, a.PRNumber)
	if err != nil {
		return fmt.Errorf("get PR: %w", err)
	}
	if pr.GetHead().GetSHA() != a.HeadSHA {
		d.Logger.Info("PR head moved, dropping results", "scan", s.scanID)
		d.finishScan(ctx, s.tenant, s.scanID, "skipped", errors.New("superseded by a newer commit"))
		return d.completeCheckRun(ctx, gh, s.owner, s.repo, s.checkRunID, "skipped", "Superseded by a newer commit",
			"A newer commit was pushed; see the check run for the latest commit.", nil)
	}

	concl := conclusion(findings, s.settings)
	rep := d.report(s.scanID, findings, ai, noChanges)
	body := render.Comment(rep)
	if len(notes) > 0 {
		d.Logger.Info("scan notes", "scan", s.scanID, "notes", notes)
	}
	err = withTenant(ctx, d, s.tenant, func(tx pgx.Tx) error {
		return persist(ctx, tx, persistIn{tenant: s.tenant, projectID: s.projectID, versionID: s.versionID, scanID: s.scanID,
			findings: findings, osvCleanRows: true, conclusion: concl, reportMD: body})
	})
	if err != nil {
		return fmt.Errorf("persist: %w", err)
	}

	title, summary, anns := render.CheckRun(rep)
	if err := d.completeCheckRun(ctx, gh, s.owner, s.repo, s.checkRunID, concl, title, summary, anns); err != nil {
		return fmt.Errorf("complete check run: %w", err)
	}

	commentID, err := d.upsertComment(ctx, gh, s.owner, s.repo, a.PRNumber, s.prevCommentID, body, concl == "success" && s.settings.SuppressClean)
	if err != nil {
		return fmt.Errorf("comment: %w", err)
	}
	if commentID != 0 {
		if err := withTenant(ctx, d, s.tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE scans SET comment_id=$2 WHERE id=$1`, s.scanID, commentID)
			return err
		}); err != nil {
			return err
		}
	}
	d.enqueueGuarddog(ctx, s.tenant, s.scanID, findings)
	d.Logger.Info("pr scan done", "scan", s.scanID, "packages", len(findings), "violations", countViolations(findings),
		"conclusion", concl, "took", since(start))
	return nil
}

// enqueueGuarddog queues heuristic analysis for newly added packages that
// have no MAL- verdict (capped per scan). Best effort.
func (d Deps) enqueueGuarddog(ctx context.Context, tenant, scanID string, fs []*finding) {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return
	}
	var params []river.InsertManyParams
	for _, f := range fs {
		if f.change != "added" || f.malware || guarddogEcosystem[f.ecosystem()] == "" || slices.ContainsFunc(params, func(p river.InsertManyParams) bool {
			return p.Args.(jobs.GuarddogAnalyze).ComponentID == f.componentID
		}) {
			continue
		}
		if len(params) == maxGuarddogJobs {
			break
		}
		params = append(params, river.InsertManyParams{Args: jobs.GuarddogAnalyze{TenantID: tenant, ComponentID: f.componentID, ScanID: scanID,
			Ecosystem: f.ecosystem(), Name: f.pkg.GetName(), Version: f.pkg.GetVersion()},
			InsertOpts: &river.InsertOpts{MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true}}})
	}
	if len(params) == 0 {
		return
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		d.Logger.Warn("enqueue guarddog", "scan", scanID, "err", err)
	}
}
