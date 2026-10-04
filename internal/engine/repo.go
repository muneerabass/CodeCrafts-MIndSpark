package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/render"
	"github.com/depguard/depguard/internal/scan"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

// fullScan evaluates every package in files and persists the result,
// replacing the version's component set and dependency edges. Files that
// are not lockfiles (manifests, LICENSE) only feed graph and license
// context. It owns the scan status update.
func (d Deps) fullScan(ctx context.Context, tenant, projectID, versionID, scanID string, st settings, files []file, notes []string, in riskInput) error {
	var lockfiles []file
	if in.aux == nil {
		in.aux = map[string][]byte{}
	}
	for _, f := range files {
		in.aux[f.Path] = f.Data
		if scan.IsManifest(f.Path) {
			lockfiles = append(lockfiles, f)
		}
	}
	manifests, n2, err := parseFiles(lockfiles)
	if err != nil {
		return err
	}
	notes = append(notes, n2...)
	changes := scan.Diff(nil, manifests)
	for i := range changes {
		changes[i].Kind = "full"
	}
	rc := d.buildRisk(ctx, manifests, in)
	findings, err := d.evaluate(ctx, changes, st, rc)
	if err != nil {
		return err
	}
	body := render.Comment(d.report(scanID, findings, nil, false, rc.project))
	if len(notes) > 0 {
		d.Logger.Info("scan notes", "scan", scanID, "notes", notes)
	}
	err = withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		if err := persist(ctx, tx, persistIn{tenant: tenant, projectID: projectID, versionID: versionID, scanID: scanID,
			findings: findings, replaceComponents: true, conclusion: conclusion(findings, st), reportMD: body, risk: rc}); err != nil {
			return err
		}
		return trackResolved(ctx, tx)
	})
	if err == nil {
		d.enqueueGuarddog(ctx, tenant, scanID, findings)
		if e := d.enqueue(ctx, jobs.Notify{TenantID: tenant, ScanID: scanID}, &river.InsertOpts{MaxAttempts: 4}); e != nil {
			d.Logger.Warn("queue alerts", "scan", scanID, "err", e)
		}
	}
	return err
}

type repoWorker struct {
	river.WorkerDefaults[jobs.ScanRepository]
	d Deps
}

func (w *repoWorker) Timeout(*river.Job[jobs.ScanRepository]) time.Duration { return 15 * time.Minute }

func (w *repoWorker) Work(ctx context.Context, job *river.Job[jobs.ScanRepository]) error {
	d, a := w.d, job.Args
	if d.Clients == nil {
		return river.JobCancel(errNoGitHub)
	}
	tenant, err := installationTenant(ctx, d.Pool, a.InstallationID)
	if err != nil {
		return err
	}
	if tenant == "" || (a.TenantID != "" && a.TenantID != tenant) {
		d.Logger.Info("installation not linked to tenant, skipping", "repo", a.RepoFullName, "tenant", a.TenantID)
		if a.ScanID != "" && a.TenantID != "" {
			d.finishScan(ctx, a.TenantID, a.ScanID, "skipped", errors.New("GitHub installation is not linked"))
		}
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
	sha := a.SHA
	if sha == "" {
		br, _, err := gh.Repositories.GetBranch(ctx, owner, repo, a.Ref, 1)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", a.Ref, err)
		}
		sha = br.GetCommit().GetSHA()
	}

	var st settings
	var project scan.Project
	var projectID, versionID, scanID string
	done := false
	err = withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		if st, err = loadSettings(ctx, tx); err != nil {
			return err
		}
		if projectID, err = ensureProject(ctx, tx, tenant, "github", a.RepoFullName, "https://github.com/"+a.RepoFullName, a.RepoID); err != nil {
			return err
		}
		if versionID, err = ensureVersion(ctx, tx, tenant, projectID, a.Ref); err != nil {
			return err
		}
		if project, err = loadProject(ctx, tx, projectID); err != nil {
			return err
		}
		scanID = a.ScanID
		if scanID == "" {
			var status string
			err := tx.QueryRow(ctx, `SELECT id, status FROM scans WHERE project_version_id=$1 AND head_sha=$2 AND trigger=$3
				ORDER BY created_at DESC LIMIT 1`, versionID, sha, a.Trigger).Scan(&scanID, &status)
			if errors.Is(err, pgx.ErrNoRows) {
				scanID = ids.New()
				_, err = tx.Exec(ctx, `INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status, head_sha)
					VALUES ($1,$2,$3,$4,$5,'queued',$6)`, scanID, tenant, projectID, versionID, a.Trigger, sha)
			} else if err == nil && status == "success" {
				done = true
				return nil
			}
			if err != nil {
				return err
			}
		}
		// Manual scans are pre-created; fill in what the API could not know.
		if _, err := tx.Exec(ctx, `UPDATE scans SET project_id=$2, project_version_id=$3, head_sha=$4 WHERE id=$1`,
			scanID, projectID, versionID, sha); err != nil {
			return err
		}
		return startScan(ctx, tx, scanID)
	})
	if err != nil || done {
		return err
	}
	if st.Disabled {
		d.finishScan(ctx, tenant, scanID, "skipped", errors.New("tenant disabled"))
		return nil
	}

	err = func() error {
		blobs, err := treeBlobs(ctx, gh, owner, repo, sha)
		if err != nil {
			return fmt.Errorf("list tree: %w", err)
		}
		var files []file
		var notes []string
		for _, e := range fullScanManifests(blobs) {
			b, err := fetchBlob(ctx, gh, owner, repo, e.GetSHA(), maxManifestBytes)
			if errors.Is(err, errTooLarge) {
				notes = append(notes, "skipped oversized "+e.GetPath())
				continue
			} else if err != nil {
				return fmt.Errorf("fetch %s: %w", e.GetPath(), err)
			}
			files = append(files, file{Path: e.GetPath(), Data: b})
		}
		return d.fullScan(ctx, tenant, projectID, versionID, scanID, st, files, notes, d.repoInputs(ctx, gh, owner, repo, blobs, files, project))
	}()
	if err != nil {
		d.finishScan(ctx, tenant, scanID, "failed", err)
		return err
	}
	d.autoFix(ctx, tenant, projectID, versionID, a.Ref)
	return nil
}

type uploadWorker struct {
	river.WorkerDefaults[jobs.ScanUpload]
	d Deps
}

func (w *uploadWorker) Timeout(*river.Job[jobs.ScanUpload]) time.Duration { return 15 * time.Minute }

func (w *uploadWorker) Work(ctx context.Context, job *river.Job[jobs.ScanUpload]) error {
	d, a := w.d, job.Args
	var st settings
	var project scan.Project
	var projectID, versionID, status string
	var files []file
	err := withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT project_id, project_version_id, status FROM scans WHERE id=$1`, a.ScanID).
			Scan(&projectID, &versionID, &status)
		if err != nil || status == "success" {
			return err
		}
		if st, err = loadSettings(ctx, tx); err != nil {
			return err
		}
		if project, err = loadProject(ctx, tx, projectID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT path, content FROM scan_uploads WHERE scan_id=$1 ORDER BY path`, a.ScanID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f file
			if err := rows.Scan(&f.Path, &f.Data); err != nil {
				return err
			}
			files = append(files, f)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return startScan(ctx, tx, a.ScanID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return river.JobCancel(fmt.Errorf("scan %s not found", a.ScanID))
	}
	if err != nil || status == "success" {
		return err
	}
	// Uploads carry lockfiles plus manifests and LICENSE files; cap lockfiles only.
	var kept []file
	n := 0
	for _, f := range files {
		if scan.IsManifest(f.Path) {
			if n++; n > maxManifests {
				continue
			}
		}
		kept = append(kept, f)
	}
	if err := d.fullScan(ctx, a.TenantID, projectID, versionID, a.ScanID, st, kept, nil, riskInput{project: project}); err != nil {
		d.finishScan(ctx, a.TenantID, a.ScanID, "failed", err)
		return err
	}
	return nil
}

// trackResolved marks the tenant's vulnerabilities whose component left the
// current inventory as resolved (fix deadlines), and reopens ones that came back.
func trackResolved(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
UPDATE component_vulnerabilities cv SET seen_current = true, resolved_at = NULL
  WHERE (NOT cv.seen_current OR cv.resolved_at IS NOT NULL)
    AND EXISTS (SELECT 1 FROM project_version_components pvc WHERE pvc.component_id = cv.component_id)`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
UPDATE component_vulnerabilities cv SET resolved_at = now()
  WHERE cv.seen_current AND cv.resolved_at IS NULL
    AND NOT EXISTS (SELECT 1 FROM project_version_components pvc WHERE pvc.component_id = cv.component_id)`)
	return err
}
