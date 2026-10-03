// Package teamcfg holds team settings stored as jsonb on tenant_settings:
// auto-fix (fix_settings) and fix deadlines (sla).
package teamcfg

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
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

// SLA is the number of days to fix a vulnerability by risk level; 0 = no deadline.
type SLA struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// DefaultSLA must match slaDays in internal/httpapi (SQL defaults).
func DefaultSLA() SLA { return SLA{Critical: 7, High: 30, Medium: 90} }

func ParseSLA(raw []byte) SLA {
	s := DefaultSLA()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

func (s SLA) Validate() error {
	for _, d := range []int{s.Critical, s.High, s.Medium, s.Low} {
		if d < 0 || d > 365 {
			return fmt.Errorf("deadlines must be between 0 and 365 days")
		}
	}
	return nil
}

// Days returns the deadline for a risk level (CRITICAL, high, ...).
func (s SLA) Days(risk string) int {
	switch strings.ToLower(risk) {
	case "critical":
		return s.Critical
	case "high":
		return s.High
	case "medium":
		return s.Medium
	case "low":
		return s.Low
	}
	return 0
}
