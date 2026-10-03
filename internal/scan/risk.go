package scan

import (
	"context"

	"github.com/safedep/vet/pkg/models"
)

// Finding categories beyond the CEL policy categories.
const (
	CategorySuspicious = "suspicious"
	CategoryLicense    = "license"
)

// Severities, highest first.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Usage models: how the scanned project is used. They drive license rules.
const (
	UsageInternal          = "internal"
	UsageSaaS              = "saas"
	UsageDistributedBinary = "distributed_binary"
	UsageDistributedSource = "distributed_source"
)

// Finding is a risk produced by a Checker (suspicious packages, license
// compliance). It is persisted as a policy_violations row.
type Finding struct {
	Rule     string // e.g. typosquat, unmaintained, license-incompatible
	Category string // CategorySuspicious | CategoryLicense
	Severity string // Severity*
	Blocking bool   // counts toward check-run failure (block mode)
	Summary  string // one plain-English sentence
	Details  map[string]any
	Package  *models.Package // the package the finding is about (required)
}

// Project describes the scanned project for project-aware checks.
type Project struct {
	Name          string
	License       string // SPDX expression; empty = unknown
	LicenseSource string // override | manifest | license_file | github | unknown
	UsageModel    string // Usage*
}

// PackageContext is dependency-graph context for a package (from BuildGraph).
type PackageContext struct {
	Direct   *bool // nil = unknown
	Depth    int   // 1 = direct; 0 = unknown
	Dev      bool
	Imported *bool // nil = unknown
}

// CheckInput is what every Checker receives after enrichment.
type CheckInput struct {
	Project  Project
	Packages []*models.Package // enriched (Insights filled)
	Context  map[*models.Package]PackageContext
}

// Checker produces findings for a scan. Implementations must not fail the scan
// for network problems: log and return what they have.
type Checker interface {
	Name() string
	Check(ctx context.Context, in CheckInput) ([]Finding, error)
}
