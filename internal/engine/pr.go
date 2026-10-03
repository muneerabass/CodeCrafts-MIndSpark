package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/ghapp"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/prsettings"
	"github.com/depguard/depguard/internal/render"
	"github.com/depguard/depguard/internal/scan"
	"github.com/google/go-github/v92/github"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/safedep/vet/pkg/models"
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
	project                      scan.Project
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
		if s.project, err = loadProject(ctx, tx, s.projectID); err != nil {
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
	rc := &riskCtx{project: s.project}
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
		// Graph context comes from the head revision's tree: manifests next
		// to the changed lockfiles, root license files and app source.
		blobs, err := treeBlobs(ctx, gh, s.owner, s.repo, a.HeadSHA)
		if err != nil {
			d.Logger.Warn("list head tree; no manifests or source for graph context", "scan", s.scanID, "err", err)
			blobs = nil
		}
		rc = d.buildRisk(ctx, head, d.repoInputs(ctx, gh, s.owner, s.repo, blobs, headFiles, s.project))
		if findings, err = d.evaluate(ctx, scan.Diff(base, head), s.settings, rc); err != nil {
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

	// Record the PR (metadata, head) and run the rule-based security review of its diff.
	var prID string
	var ps prsettings.Settings
	if err := withTenant(ctx, d, s.tenant, func(tx pgx.Tx) error {
		var err error
		ps = loadPRSettings(ctx, tx)
		prID, err = ghapp.UpsertPR(ctx, tx, s.tenant, a.InstallationID, &github.Repository{ID: github.Ptr(a.RepoID), FullName: github.Ptr(a.RepoFullName)}, pr)
		return err
	}); err != nil {
		return fmt.Errorf("record PR: %w", err)
	}
	diffFiles, err := prFiles(ctx, gh, s.owner, s.repo, a.PRNumber)
	if err != nil {
		return fmt.Errorf("list PR diff: %w", err)
	}
	aiOn := ps.AIReview.Enabled && d.LLM.Enabled()
	aiNote := ""
	switch {
	case !ps.AIReview.Enabled:
		aiNote = "turned off in Settings → Pull requests"
	case !d.LLM.Enabled():
		aiNote = "no AI model is configured on the server"
	}
	rv, err := d.storeRulesReview(ctx, s.tenant, prID, s.scanID, a.HeadSHA, diffFiles, aiOn, aiNote)
	if err != nil {
		return fmt.Errorf("store review: %w", err)
	}

	concl := conclusion(findings, s.settings)
	// Leaked secrets found by the rules fail the check like a blocking policy violation.
	secrets := 0
	for _, f := range rv.Findings {
		if f.Severity == "critical" {
			secrets++
		}
	}
	if secrets > 0 && s.settings.BlockMode {
		concl = "failure"
	} else if secrets > 0 && concl == "success" {
		concl = "neutral"
	}
	rep := d.report(s.scanID, findings, ai, noChanges, rc.project)
	summary := render.Summarize(rep, concl)
	if len(notes) > 0 {
		d.Logger.Info("scan notes", "scan", s.scanID, "notes", notes)
	}
	err = withTenant(ctx, d, s.tenant, func(tx pgx.Tx) error {
		if err := persist(ctx, tx, persistIn{tenant: s.tenant, projectID: s.projectID, versionID: s.versionID, scanID: s.scanID,
			findings: findings, osvCleanRows: true, conclusion: concl, reportMD: render.Comment(rep), risk: rc}); err != nil {
			return err
		}
		sj, _ := json.Marshal(summary)
		if _, err := tx.Exec(ctx, `UPDATE scans SET pr_summary=$2 WHERE id=$1`, s.scanID, sj); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE pull_requests SET latest_scan_id=$2, updated_at=now() WHERE id=$1`, prID, s.scanID)
		return err
	})
	if err != nil {
		return fmt.Errorf("persist: %w", err)
	}

	title, checkSummary, anns := render.CheckRun(rep)
	if secrets > 0 {
		title = fmt.Sprintf("%s · %d critical security issue(s) found in the code", title, secrets)
		for _, f := range rv.Findings {
			if f.Severity == "critical" && f.Line > 0 {
				anns = append(anns, render.Annotation{Path: f.File, Line: f.Line, Level: "failure", Title: f.Title, Message: f.Explanation + " " + f.Suggestion})
			}
		}
	}
	if err := d.completeCheckRun(ctx, gh, s.owner, s.repo, s.checkRunID, concl, title, checkSummary, anns); err != nil {
		return fmt.Errorf("complete check run: %w", err)
	}

	// Rank the PR and post the comment and labels; the AI review updates them when it finishes.
	if err := d.refreshPR(ctx, gh, s.tenant, prID); err != nil {
		return fmt.Errorf("update PR comment: %w", err)
	}
	if aiOn {
		if err := d.enqueue(ctx, jobs.ReviewPullRequest{TenantID: s.tenant, InstallationID: a.InstallationID, PRID: prID, HeadSHA: a.HeadSHA},
			&river.InsertOpts{MaxAttempts: 10, UniqueOpts: river.UniqueOpts{ByArgs: true}}); err != nil {
			d.Logger.Warn("enqueue AI review", "scan", s.scanID, "err", err)
		}
	}
	d.enqueueGuarddog(ctx, s.tenant, s.scanID, findings)
	d.Logger.Info("pr scan done", "scan", s.scanID, "packages", len(findings), "violations", countViolations(findings),
		"conclusion", concl, "took", since(start))
	return nil
}

// enqueueGuarddog queues heuristic analysis for added (PR) or all (full
// scan) packages that have no MAL- verdict, capped per scan and ordered by
// PrioritizeGuarddog. Best effort.
func (d Deps) enqueueGuarddog(ctx context.Context, tenant, scanID string, fs []*finding) {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return
	}
	byPkg := map[*models.Package]*finding{}
	var pkgs []*models.Package
	var checks []scan.Finding
	for _, f := range fs {
		if (f.change != "added" && f.change != "full") || f.malware || guarddogEcosystem[f.ecosystem()] == "" {
			continue
		}
		byPkg[f.pkg] = f
		pkgs = append(pkgs, f.pkg)
		checks = append(checks, f.checks...)
	}
	if d.PrioritizeGuarddog != nil {
		pkgs = d.PrioritizeGuarddog(pkgs, checks)
	}
	limit := d.MaxGuarddogJobs
	if limit <= 0 {
		limit = defaultGuarddogJobs
	}
	var params []river.InsertManyParams
	seen := map[string]bool{}
	for _, p := range pkgs {
		f := byPkg[p]
		if f == nil || seen[f.componentID] {
			continue
		}
		if len(params) == limit {
			break
		}
		seen[f.componentID] = true
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
