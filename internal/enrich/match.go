package enrich

import (
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

func (e osvEvent) version() string {
	for _, v := range []string{e.Introduced, e.Fixed, e.LastAffected, e.Limit} {
		if v != "" {
			return v
		}
	}
	return ""
}

// parse parses a version for an OSV ecosystem; SEMVER ranges and ecosystems
// semantic doesn't know (e.g. "GitHub Actions") fall back to SemVer.
func parse(ver, eco, rangeType string) (semantic.Version, error) {
	if rangeType != "SEMVER" {
		if v, err := semantic.Parse(ver, eco); err == nil {
			return v, nil
		}
	}
	return semantic.Parse(ver, "npm")
}

// CompareVersions compares two versions of a package in its OSV ecosystem's
// version scheme (npm semver, PEP 440, Go, crates.io, ...): -1, 0 or 1.
func CompareVersions(osvEco, a, b string) (int, error) {
	v, err := parse(a, osvEco, "ECOSYSTEM")
	if err != nil {
		return 0, err
	}
	return v.CompareStr(b)
}

// OSVEcosystemName maps a vet ecosystem name to its OSV name, "" if unsupported.
func OSVEcosystemName(vetEco string) string { return osvEcosystems[vetEco] }

// affects reports whether version is affected per an OSV affected[] entry:
// explicit versions[] or any SEMVER/ECOSYSTEM range (GIT ranges ignored).
// Port of osv-scalibr's osvlocal matcher.
func affects(eco, version string, versions []string, ranges []osvRange) bool {
	bare := strings.TrimPrefix(version, "v")
	for _, v := range versions {
		if v == version || strings.TrimPrefix(v, "v") == bare {
			return true
		}
	}
	for _, r := range ranges {
		if (r.Type == "SEMVER" || r.Type == "ECOSYSTEM") && rangeContains(eco, version, r) {
			return true
		}
	}
	return false
}

func rangeContains(eco, version string, r osvRange) bool {
	vp, err := parse(version, eco, r.Type)
	if err != nil || len(r.Events) == 0 {
		return false
	}
	events := slices.Clone(r.Events)
	slices.SortStableFunc(events, func(a, b osvEvent) int {
		switch {
		case a.Introduced == "0" && b.Introduced == "0":
			return 0
		case a.Introduced == "0":
			return -1
		case b.Introduced == "0":
			return 1
		}
		av, err := parse(a.version(), eco, r.Type)
		if err != nil {
			return 0
		}
		c, _ := av.CompareStr(b.version())
		return c
	})
	affected := false
	for _, e := range events {
		switch {
		case affected && e.Fixed != "":
			c, err := vp.CompareStr(e.Fixed)
			affected = err == nil && c < 0
		case affected && e.LastAffected != "":
			c, err := vp.CompareStr(e.LastAffected)
			affected = e.LastAffected == version || (err == nil && c <= 0)
		case !affected && e.Introduced != "":
			c, err := vp.CompareStr(e.Introduced)
			affected = e.Introduced == "0" || (err == nil && c >= 0)
		}
	}
	return affected
}

// fixedIn returns the lowest "fixed" event above version among the
// SEMVER/ECOSYSTEM ranges that contain version ("" if none).
func fixedIn(eco, version string, ranges []osvRange) string {
	best := ""
	var bestV semantic.Version
	for _, r := range ranges {
		if (r.Type != "SEMVER" && r.Type != "ECOSYSTEM") || !rangeContains(eco, version, r) {
			continue
		}
		vp, err := parse(version, eco, r.Type)
		if err != nil {
			continue
		}
		for _, e := range r.Events {
			if e.Fixed == "" {
				continue
			}
			if c, err := vp.CompareStr(e.Fixed); err != nil || c >= 0 {
				continue
			}
			if best == "" {
				if fv, err := parse(e.Fixed, eco, r.Type); err == nil {
					best, bestV = e.Fixed, fv
				}
			} else if c, err := bestV.CompareStr(e.Fixed); err == nil && c > 0 {
				fv, _ := parse(e.Fixed, eco, r.Type)
				best, bestV = e.Fixed, fv
			}
		}
	}
	return best
}
