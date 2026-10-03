// Package teamcfg holds team settings stored as jsonb on tenant_settings:
// auto-fix (fix_settings).
package teamcfg

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Fix configures automatic fix pull requests.
type Fix struct {
	Auto    bool     `json:"auto"`     // open fix PRs after default-branch scans
	Levels  []string `json:"levels"`   // risk levels fixed automatically
	KEV     bool     `json:"kev"`      // also fix actively exploited vulnerabilities at any level
	MaxOpen int      `json:"max_open"` // cap of open automatic fix PRs per project
}

func DefaultFix() Fix { return Fix{Levels: []string{"critical"}, KEV: true, MaxOpen: 5} }

// ParseFix reads stored JSON over the defaults.
func ParseFix(raw []byte) Fix {
	f := DefaultFix()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &f)
	}
	if f.MaxOpen <= 0 {
		f.MaxOpen = 5
	}
	return f
}

var riskLevels = []string{"critical", "high", "medium", "low"}

func (f Fix) Validate() error {
	for _, l := range f.Levels {
		if !slices.Contains(riskLevels, l) {
			return fmt.Errorf("unknown level %q", l)
		}
	}
	if f.MaxOpen < 1 || f.MaxOpen > 20 {
		return fmt.Errorf("max_open must be between 1 and 20")
	}
	return nil
}
