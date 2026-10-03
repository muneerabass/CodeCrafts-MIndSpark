// Package jobs defines River job argument types shared by producers (api) and
// consumers (worker). Workers live in their owning packages.
package jobs

// ScanPullRequest scans only packages added/changed by a PR and reports back
// via Check Run + sticky comment.
type ScanPullRequest struct {
	InstallationID int64  `json:"installation_id"`
	RepoID         int64  `json:"repo_id"`
	RepoFullName   string `json:"repo_full_name"`
	PRNumber       int    `json:"pr_number"`
	BaseSHA        string `json:"base_sha"`
	HeadSHA        string `json:"head_sha"`
	BaseRef        string `json:"base_ref"`
	HeadRef        string `json:"head_ref"`
	IsDraft        bool   `json:"is_draft"`
}

func (ScanPullRequest) Kind() string { return "scan_pull_request" }

// ScanRepository runs a full scan of a branch (push to default branch, or a
// manual "Scan a repository" request).
type ScanRepository struct {
	TenantID       string `json:"tenant_id"`
	InstallationID int64  `json:"installation_id"`
	RepoID         int64  `json:"repo_id"`
	RepoFullName   string `json:"repo_full_name"`
	Ref            string `json:"ref"`     // branch name
	SHA            string `json:"sha"`     // optional; resolved from Ref if empty
	Trigger        string `json:"trigger"` // push | manual
	ScanID         string `json:"scan_id"` // pre-created queued scan row (manual); empty for push
}

func (ScanRepository) Kind() string { return "scan_repository" }

// ScanUpload scans lockfiles uploaded through POST /v1/scans (CLI, CI pipelines).
type ScanUpload struct {
	TenantID string `json:"tenant_id"`
	ScanID   string `json:"scan_id"` // pre-created queued scan row; lockfiles stored under it
}

func (ScanUpload) Kind() string { return "scan_upload" }

// GuarddogAnalyze runs heuristic malware analysis on a newly seen package.
type GuarddogAnalyze struct {
	TenantID    string `json:"tenant_id"`
	ComponentID string `json:"component_id"`
	ScanID      string `json:"scan_id"`
	Ecosystem   string `json:"ecosystem"`
	Name        string `json:"name"`
	Version     string `json:"version"`
}

func (GuarddogAnalyze) Kind() string { return "guarddog_analyze" }

// SyncInstallation reconciles repositories of a GitHub App installation.
type SyncInstallation struct {
	InstallationID int64 `json:"installation_id"`
}

func (SyncInstallation) Kind() string { return "sync_installation" }

// CleanupScanUploads removes scan_uploads rows for scans that have finished
// (success/failed/skipped) and for abandoned queued/running scans older than
// the retention window. Scheduled by the worker; retries are preserved because
// River keeps a scan in a non-terminal status until MaxAttempts is reached.
type CleanupScanUploads struct{}

func (CleanupScanUploads) Kind() string { return "cleanup_scan_uploads" }
