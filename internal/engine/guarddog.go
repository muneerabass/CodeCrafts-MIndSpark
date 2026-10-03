package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/scan"
	"github.com/depguard/depguard/internal/suspicious"
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
	Issues    int            `json:"issues"`
	Errors    map[string]any `json:"errors"`
	Results   map[string]any `json:"results"`
	RiskScore *struct {
		Score *float64 `json:"score"`
	} `json:"risk_score"`
}

// guarddogVerdict is a guarddog_verdict row: one analysis of a package
// version, shared by all tenants. Output is guarddog's full JSON document.
type guarddogVerdict struct {
	Issues int
	Rules  []string
	Output []byte
	Error  string
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
	v, err := loadGuarddogVerdict(ctx, d, a)
	if err != nil {
		d.Logger.Warn("guarddog verdict cache read failed", "pkg", a.Name, "err", err)
	}
	if v == nil {
		if v, err = runGuarddogVerdict(ctx, d, eco, a); err != nil || v == nil {
			return err
		}
		if a.Version != "" { // an unversioned scan analyses "latest", which changes over time
			if _, err := d.Pool.Exec(ctx, `INSERT INTO guarddog_verdict (ecosystem, name, version, issues, rules, results, error, analyzed_at)
				VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), now())
				ON CONFLICT (ecosystem, name, version) DO UPDATE SET issues = EXCLUDED.issues, rules = EXCLUDED.rules,
				  results = EXCLUDED.results, error = EXCLUDED.error, analyzed_at = now()`,
				a.Ecosystem, a.Name, a.Version, v.Issues, v.Rules, v.Output, v.Error); err != nil {
				d.Logger.Warn("guarddog verdict cache write failed", "pkg", a.Name, "err", err)
			}
		}
	}
	var prID string
	var inst int64
	err = withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
		if err := recordGuarddog(ctx, tx, a, v); err != nil {
			return err
		}
		if v.Issues == 0 {
			return nil
		}
		// A suspicious package in a PR: re-rank the PR and update its comment and labels.
		err := tx.QueryRow(ctx, `SELECT id, COALESCE(installation_id, 0) FROM pull_requests WHERE latest_scan_id=$1`, a.ScanID).Scan(&prID, &inst)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil || prID == "" {
		return err
	}
	if err := d.enqueue(ctx, jobs.RefreshPullRequest{TenantID: a.TenantID, InstallationID: inst, PRID: prID},
		&river.InsertOpts{MaxAttempts: 5}); err != nil {
		d.Logger.Warn("enqueue PR refresh after guarddog", "pr", prID, "err", err)
	}
	return nil
}

func loadGuarddogVerdict(ctx context.Context, d Deps, a jobs.GuarddogAnalyze) (*guarddogVerdict, error) {
	if a.Version == "" {
		return nil, nil
	}
	v := &guarddogVerdict{}
	err := d.Pool.QueryRow(ctx, `SELECT issues, rules, results, coalesce(error, '') FROM guarddog_verdict
		WHERE ecosystem=$1 AND name=$2 AND version=$3`, a.Ecosystem, a.Name, a.Version).Scan(&v.Issues, &v.Rules, &v.Output, &v.Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// runGuarddogVerdict runs the guarddog CLI. A nil verdict without error means
// guarddog produced nothing usable (not cached, nothing recorded).
func runGuarddogVerdict(ctx context.Context, d Deps, eco string, a jobs.GuarddogAnalyze) (*guarddogVerdict, error) {
	bin, err := exec.LookPath(d.GuarddogBin)
	if err != nil {
		d.Logger.Error("guarddog binary not found; set GUARDDOG_BIN", "bin", d.GuarddogBin, "err", err)
		return nil, river.JobCancel(fmt.Errorf("guarddog unavailable: %w", err))
	}
	out, err := runGuarddog(ctx, bin, eco, a.Name, a.Version, true)
	if err != nil && d.GuarddogAllowNoSandbox && strings.Contains(strings.ToLower(err.Error()), "sandbox") {
		d.Logger.Warn("guarddog sandbox unavailable, retrying without it", "pkg", a.Name)
		out, err = runGuarddog(ctx, bin, eco, a.Name, a.Version, false)
	}
	if err != nil {
		return nil, err
	}
	var res guarddogResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("guarddog output: %w", err)
	}
	if res.Issues == 0 && len(res.Errors) > 0 && len(res.Results) == 0 {
		d.Logger.Warn("guarddog produced no verdict", "pkg", a.Name, "version", a.Version, "errors", res.Errors)
		return nil, nil
	}
	v := &guarddogVerdict{Issues: res.Issues, Output: out}
	for rule, findings := range res.Results {
		if nonEmpty(findings) {
			v.Rules = append(v.Rules, rule)
		}
	}
	sort.Strings(v.Rules)
	if len(res.Errors) > 0 {
		b, _ := json.Marshal(res.Errors)
		v.Error = trunc(string(b), 2000)
	}
	return v, nil
}

// nonEmpty reports whether a guarddog rule result holds findings.
func nonEmpty(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case string:
		return v != ""
	case bool:
		return v
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	}
	return true
}

// recordGuarddog writes the tenant's package_analyses row and, for a
// suspicious verdict, bumps the scan counter and adds an unusual-behaviour
// policy violation (unless the tenant's policy disables it).
func recordGuarddog(ctx context.Context, tx pgx.Tx, a jobs.GuarddogAnalyze, v *guarddogVerdict) error {
	status := "clean"
	if v.Issues > 0 {
		status = "suspicious"
	}
	_, err := tx.Exec(ctx, `INSERT INTO package_analyses (id, tenant_id, component_id, project_version_id, scan_id, status, verified, source, evidence)
		SELECT $1, $2, $3, (SELECT project_version_id FROM scans WHERE id=$4), NULLIF($4,''), $5, false, 'guarddog', $6`,
		ids.New(), a.TenantID, a.ComponentID, a.ScanID, status, v.Output)
	if err != nil || status != "suspicious" {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE scans SET suspicious_count=suspicious_count+1 WHERE id=$1`, a.ScanID); err != nil {
		return err
	}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT policy FROM tenant_settings`).Scan(&raw); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	pc, err := scan.ParsePolicy(raw)
	if err != nil {
		pc = scan.PolicyConfig{} // invalid policy: defaults, as loadSettings does
	}
	cfg := suspicious.ConfigFromPolicy(pc)
	if !cfg.UnusualBehaviour {
		return nil
	}
	var res guarddogResult
	_ = json.Unmarshal(v.Output, &res)
	var score *float64
	if res.RiskScore != nil {
		score = res.RiskScore.Score
	}
	rules := v.Rules
	if rules == nil {
		rules = []string{}
	}
	details, _ := json.Marshal(map[string]any{"rules": rules, "risk_score": score})
	summary := "Suspicious behaviour detected by heuristics"
	if len(rules) > 0 {
		summary += ": " + strings.Join(rules, ", ")
	}
	_, err = tx.Exec(ctx, `INSERT INTO policy_violations (id, tenant_id, scan_id, project_version_id, component_id, rule_name, category,
		  summary, severity, blocking, details)
		SELECT $1, $2, s.id, s.project_version_id, $4, $5, $6, $7, $8, $9, $10 FROM scans s
		WHERE s.id = $3 AND s.project_version_id IS NOT NULL`,
		ids.New(), a.TenantID, a.ScanID, a.ComponentID, suspicious.RuleUnusualBehaviour, scan.CategorySuspicious,
		summary, scan.SeverityHigh, cfg.Blocking[suspicious.RuleUnusualBehaviour], details)
	return err
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
