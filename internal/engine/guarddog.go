package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/safedep/vet/pkg/models"
)

// guarddogEcosystem maps vet ecosystems to guarddog's CLI names.
var guarddogEcosystem = map[string]string{
	models.EcosystemNpm:      "npm",
	models.EcosystemPyPI:     "pypi",
	models.EcosystemGo:       "go",
	models.EcosystemRubyGems: "rubygems",
	models.EcosystemCargo:    "crates",
}

const guarddogTimeout = 120 * time.Second

type guarddogWorker struct {
	river.WorkerDefaults[jobs.GuarddogAnalyze]
	d Deps
}

func (w *guarddogWorker) Timeout(*river.Job[jobs.GuarddogAnalyze]) time.Duration {
	return 5 * time.Minute
}

type guarddogResult struct {
	Issues  int            `json:"issues"`
	Errors  map[string]any `json:"errors"`
	Results map[string]any `json:"results"`
}

func (w *guarddogWorker) Work(ctx context.Context, job *river.Job[jobs.GuarddogAnalyze]) error {
	d, a := w.d, job.Args
	eco := guarddogEcosystem[a.Ecosystem]
	if eco == "" || a.Name == "" || strings.HasPrefix(a.Name, "-") || strings.HasPrefix(a.Version, "-") {
		return nil // unsupported ecosystem or argument-injection attempt
	}
	var exists bool
	if err := withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM package_analyses WHERE component_id=$1 AND source='guarddog')`, a.ComponentID).Scan(&exists)
	}); err != nil || exists {
		return err
	}
	bin, err := exec.LookPath(d.GuarddogBin)
	if err != nil {
		d.Logger.Error("guarddog binary not found; set GUARDDOG_BIN", "bin", d.GuarddogBin, "err", err)
		return river.JobCancel(fmt.Errorf("guarddog unavailable: %w", err))
	}
	out, err := runGuarddog(ctx, bin, eco, a.Name, a.Version, true)
	if err != nil && d.GuarddogAllowNoSandbox && strings.Contains(strings.ToLower(err.Error()), "sandbox") {
		d.Logger.Warn("guarddog sandbox unavailable, retrying without it", "pkg", a.Name)
		out, err = runGuarddog(ctx, bin, eco, a.Name, a.Version, false)
	}
	if err != nil {
		return err
	}
	var res guarddogResult
	if err := json.Unmarshal(out, &res); err != nil {
		return fmt.Errorf("guarddog output: %w", err)
	}
	if res.Issues == 0 && len(res.Errors) > 0 && len(res.Results) == 0 {
		d.Logger.Warn("guarddog produced no verdict", "pkg", a.Name, "version", a.Version, "errors", res.Errors)
		return nil
	}
	status := "clean"
	if res.Issues > 0 {
		status = "suspicious"
	}
	return withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO package_analyses (id, tenant_id, component_id, project_version_id, scan_id, status, verified, source, evidence)
			SELECT $1, $2, $3, (SELECT project_version_id FROM scans WHERE id=$4), NULLIF($4,''), $5, false, 'guarddog', $6`,
			ids.New(), a.TenantID, a.ComponentID, a.ScanID, status, out)
		if err == nil && status == "suspicious" {
			_, err = tx.Exec(ctx, `UPDATE scans SET suspicious_count=suspicious_count+1 WHERE id=$1`, a.ScanID)
		}
		return err
	})
}

func runGuarddog(ctx context.Context, bin, eco, name, version string, sandbox bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, guarddogTimeout)
	defer cancel()
	args := []string{eco, "scan", name, "--output-format=json"}
	if version != "" {
		args = append(args, "--version", version)
	}
	if !sandbox {
		args = append(args, "--no-sandbox")
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = os.TempDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("guarddog timed out after %s", guarddogTimeout)
		}
		return nil, fmt.Errorf("guarddog: %w: %s", err, trunc(strings.TrimSpace(stderr.String()+" "+stdout.String()), 2000))
	}
	return stdout.Bytes(), nil
}
