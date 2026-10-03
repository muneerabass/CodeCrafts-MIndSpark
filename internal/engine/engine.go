// Package engine runs scans as River jobs: fetch manifests from GitHub (or
// uploads) → parse with vet → diff (PRs) → enrich → policy → persist → report
// via Check Run and sticky PR comment.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/ghapp"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/scan"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/riverqueue/river"
	"github.com/safedep/vet/pkg/models"
)

// Enricher fills pkg.Insights (vulns incl. MAL-, licenses, projects, scorecard).
// Implemented by internal/enrich.
type Enricher interface {
	Enrich(ctx context.Context, pkgs []*models.Package) error
}

// Deps are shared by all workers.
type Deps struct {
	Pool     *pgxpool.Pool
	Clients  githubapp.ClientCreator // nil: GitHub jobs are cancelled
	GitHub   ghapp.Config            // Slug (to find our comments), CheckRunName
	Enricher Enricher
	// PublicURL is the web app base URL used for report links.
	PublicURL string
	// GuarddogBin defaults to "guarddog"; AllowNoSandbox permits one retry
	// with --no-sandbox when the kernel sandbox is unavailable.
	GuarddogBin            string
	GuarddogAllowNoSandbox bool
	// DisableXBOM turns off AI/SaaS usage detection on changed source files.
	DisableXBOM bool
	Logger      *slog.Logger
}

// AddWorkers registers ScanPullRequest, ScanRepository, ScanUpload,
// GuarddogAnalyze and SyncInstallation workers.
func AddWorkers(w *river.Workers, d Deps) {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.GitHub.CheckRunName == "" {
		d.GitHub.CheckRunName = ghapp.DefaultCheckRunName
	}
	if d.GuarddogBin == "" {
		d.GuarddogBin = "guarddog"
	}
	river.AddWorker(w, &prWorker{d: d})
	river.AddWorker(w, &repoWorker{d: d})
	river.AddWorker(w, &uploadWorker{d: d})
	river.AddWorker(w, &guarddogWorker{d: d})
	river.AddWorker(w, &syncWorker{d: d})
}

// Size limits for anything fetched from repositories.
const (
	maxManifestBytes = 10 << 20
	maxManifests     = 50
	maxSourceBytes   = 1 << 20
	maxSourceTotal   = 20 << 20
	maxGuarddogJobs  = 25
)

var errNoGitHub = errors.New("engine: GitHub App not configured")

// settings are a tenant's scan preferences, policy and exclusions.
type settings struct {
	BlockMode     bool
	SuppressClean bool
	Disabled      bool
	Rules         []scan.Rule
	Exclusions    []scan.Exclusion
}

func loadSettings(ctx context.Context, tx pgx.Tx) (settings, error) {
	st := settings{BlockMode: true}
	var policy []byte
	err := tx.QueryRow(ctx, `SELECT block_mode, suppress_clean_comments, disabled_at IS NOT NULL, policy FROM tenant_settings`).
		Scan(&st.BlockMode, &st.SuppressClean, &st.Disabled, &policy)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return st, err
	}
	if st.Rules, err = scan.RulesFromPolicy(policy); err != nil {
		return st, err
	}
	if _, err := scan.NewPolicy(st.Rules); err != nil {
		slog.Warn("tenant policy invalid, using defaults", "err", err)
		st.Rules = scan.DefaultRules()
	}
	rows, err := tx.Query(ctx, `SELECT ecosystem, name, version, expires_at FROM exclusions WHERE expires_at IS NULL OR expires_at > now()`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var e scan.Exclusion
		if err := rows.Scan(&e.Ecosystem, &e.Name, &e.Version, &e.ExpiresAt); err != nil {
			return st, err
		}
		st.Exclusions = append(st.Exclusions, e)
	}
	return st, rows.Err()
}

// installationTenant returns the tenant of a linked installation, or "".
func installationTenant(ctx context.Context, pool *pgxpool.Pool, installationID int64) (string, error) {
	var tenant string
	err := db.WithSystemTx(ctx, pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT tenant_id FROM gh_installations WHERE id=$1 AND status='linked' AND tenant_id IS NOT NULL`,
			installationID).Scan(&tenant)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return tenant, err
}

func ensureProject(ctx context.Context, tx pgx.Tx, tenant, source, name, url string, ghRepoID int64) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO projects (id, tenant_id, source, name, url, gh_repo_id) VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,0))
		ON CONFLICT (tenant_id, source, name) DO UPDATE SET url=COALESCE(EXCLUDED.url, projects.url),
		  gh_repo_id=COALESCE(EXCLUDED.gh_repo_id, projects.gh_repo_id), updated_at=now()
		RETURNING id`, ids.New(), tenant, source, name, url, ghRepoID).Scan(&id)
	return id, err
}

func ensureVersion(ctx context.Context, tx pgx.Tx, tenant, projectID, name string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ($1,$2,$3,$4)
		ON CONFLICT (project_id, name) DO UPDATE SET updated_at=now() RETURNING id`, ids.New(), tenant, projectID, name).Scan(&id)
	return id, err
}

// file is a repository file fetched for scanning.
type file struct {
	Path string // repo-relative, slash separated
	Data []byte
}

// writeFiles writes files under dir using os.Root, which rejects any path
// escaping dir (.., absolute paths, symlinks). Unsafe paths are skipped.
func writeFiles(dir string, files []file) ([]scan.Lockfile, []string) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, []string{err.Error()}
	}
	defer root.Close()
	var out []scan.Lockfile
	var notes []string
	for _, f := range files {
		p := filepath.FromSlash(f.Path)
		if !filepath.IsLocal(p) {
			notes = append(notes, "skipped unsafe path "+f.Path)
			continue
		}
		if err := root.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			notes = append(notes, "skipped "+f.Path+": "+err.Error())
			continue
		}
		if err := root.WriteFile(p, f.Data, 0o600); err != nil {
			notes = append(notes, "skipped "+f.Path+": "+err.Error())
			continue
		}
		out = append(out, scan.Lockfile{Path: filepath.Join(dir, p), RepoPath: f.Path})
	}
	return out, notes
}

// parseFiles writes files into a fresh temp dir and parses each with vet;
// a file that fails to parse is reported in notes, not fatal.
func parseFiles(files []file) ([]*models.PackageManifest, []string, error) {
	if len(files) == 0 {
		return nil, nil, nil
	}
	dir, err := os.MkdirTemp("", "depguard-scan-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	lfs, notes := writeFiles(dir, files)
	var out []*models.PackageManifest
	for _, lf := range lfs {
		ms, err := scan.Parse([]scan.Lockfile{lf})
		if err != nil {
			notes = append(notes, fmt.Sprintf("could not parse %s", lf.RepoPath))
			continue
		}
		out = append(out, ms...)
	}
	return out, notes, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func since(t time.Time) string { return time.Since(t).Round(time.Millisecond).String() }
