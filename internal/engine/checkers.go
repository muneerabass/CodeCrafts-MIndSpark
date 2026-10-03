package engine

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/safedep/vet/pkg/models"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/license"
	"github.com/depguard/depguard/internal/pkgrules"
	"github.com/depguard/depguard/internal/scan"
	"github.com/depguard/depguard/internal/suspicious"
)

// StandardCheckers returns the risk checkers configured by the tenant policy:
// suspicious packages, license compliance and package/version rules.
func StandardCheckers(pool *pgxpool.Pool, e *enrich.Enricher) func(scan.PolicyConfig, scan.Project) []scan.Checker {
	return func(p scan.PolicyConfig, _ scan.Project) []scan.Checker {
		out := []scan.Checker{suspicious.New(pool, e, suspicious.ConfigFromPolicy(p))}
		lic := scan.LicensePreset{Enabled: true, BlockingSeverity: scan.SeverityHigh}
		if p.Presets != nil {
			lic = p.Presets.License
			if len(p.Presets.Packages) > 0 {
				out = append(out, pkgrules.New(p.Presets.Packages))
			}
		}
		if lic.Enabled {
			// Deny is enforced by the CEL denied-license rule; passing it here too would report twice.
			out = append(out, license.New(license.Config{BlockingSeverity: lic.BlockingSeverity}))
		}
		return out
	}
}

func trusted(p scan.PolicyConfig, pkg *models.Package) bool {
	return p.Presets != nil && pkgrules.Trusted(p.Presets.Packages, pkg)
}
