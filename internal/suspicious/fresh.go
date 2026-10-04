package suspicious

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/registry"
	"github.com/depguard/depguard/internal/scan"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/safedep/vet/pkg/models"
)

// Fresh-release rules (registry metadata).
const (
	RuleReleaseAge         = "release-age"
	RuleInstallScriptAdded = "install-script-added"
	RuleProvenanceDropped  = "provenance-dropped"
	RulePublisherChanged   = "publisher-changed"
	RuleNewBehaviour       = "new-behaviour" // written by the guarddog worker (diff against the previous release)
)

// historyWindow: only recent releases are compared with their predecessor.
const historyWindow = 90 * 24 * time.Hour

func freshOn(p scan.FreshPreset) bool {
	return p.CooldownHours > 0 || p.InstallScripts || p.Provenance || p.Publisher
}

func registryKey(p *models.Package) registry.Pkg {
	eco := enrich.OSVEcosystem(p)
	return registry.Pkg{Eco: eco, Name: p.GetName(), Norm: feeds.NormalizeName(eco, p.GetName())}
}

// loadFresh reads registry releases and the versions that fix a known advisory.
func (c *checker) loadFresh(ctx context.Context, pkgs []*models.Package, f *facts) {
	seen := map[registry.Pkg]bool{}
	var keys []registry.Pkg
	for _, p := range pkgs {
		// Old releases (deps.dev publish date known and past the window) can't trip
		// these rules; skipping them keeps a first full scan from fetching every packument.
		if t, ok := f.published[p]; ok && c.now().Sub(t) > historyWindow {
			continue
		}
		if k := registryKey(p); registry.Supported(k.Eco) && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	f.releases = c.reg.Cached(ctx, c.pool, keys)
	if c.cfg.Fresh.AllowSecurityFixes && c.cfg.Fresh.CooldownHours > 0 {
		f.securityFixes = securityFixes(ctx, c.pool, keys)
	}
}

// securityFixes returns "eco/name@version" for versions that an OSV advisory lists as its fix.
func securityFixes(ctx context.Context, pool *pgxpool.Pool, keys []registry.Pkg) map[string]bool {
	out := map[string]bool{}
	var ecos, names []string
	for _, k := range keys {
		ecos, names = append(ecos, k.Eco), append(names, k.Norm)
	}
	rows, err := pool.Query(ctx, `SELECT DISTINCT a.ecosystem, a.name_norm, ev->>'fixed'
		FROM affected a, jsonb_array_elements(a.ranges) r, jsonb_array_elements(r->'events') ev
		WHERE (a.ecosystem, a.name_norm) IN (SELECT * FROM unnest($1::text[], $2::text[])) AND ev ? 'fixed'`, ecos, names)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var eco, name, v string
		if rows.Scan(&eco, &name, &v) == nil {
			out[eco+"/"+name+"@"+v] = true
		}
	}
	return out
}

func ago(d time.Duration) string {
	switch h := int(d.Hours()); {
	case h < 1:
		return fmt.Sprintf("%d minutes ago", max(1, int(d.Minutes())))
	case h == 1:
		return "1 hour ago"
	case h < 48:
		return fmt.Sprintf("%d hours ago", h)
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// evaluateFresh flags risky properties of a brand-new release.
func (c *checker) evaluateFresh(p *models.Package, f facts) []scan.Finding {
	cfg := c.cfg.Fresh
	k := registryKey(p)
	cur, prev := registry.Find(f.releases[k], p.GetVersion())
	if cur == nil {
		return nil
	}
	now := c.now()
	age := now.Sub(cur.Published)
	label := p.GetName() + "@" + p.GetVersion()
	mk := func(rule, sev string, blocking bool, summary string, d map[string]any) scan.Finding {
		d["published"] = cur.Published.UTC().Format(time.RFC3339)
		return scan.Finding{Rule: rule, Category: scan.CategorySuspicious, Severity: sev, Blocking: blocking && cfg.Block, Summary: summary, Details: d, Package: p}
	}
	var out []scan.Finding
	if cool := time.Duration(cfg.CooldownHours) * time.Hour; cool > 0 && age < cool {
		if cfg.AllowSecurityFixes && f.securityFixes[k.Eco+"/"+k.Norm+"@"+p.GetVersion()] {
			// A release that fixes a known advisory is let through: waiting would leave the hole open.
		} else {
			out = append(out, mk(RuleReleaseAge, scan.SeverityHigh, true,
				fmt.Sprintf("%s was published %s; depguard waits %d hours before allowing new releases", label, ago(age), cfg.CooldownHours),
				map[string]any{"age_hours": int(age.Hours()), "cooldown_hours": cfg.CooldownHours}))
		}
	}
	if prev == nil || age > historyWindow || k.Eco != "npm" {
		return out
	}
	var added, dropped bool
	if cfg.InstallScripts && len(cur.Scripts) > 0 && !maps.Equal(cur.Scripts, prev.Scripts) {
		added = len(prev.Scripts) == 0
		names := slices.Sorted(maps.Keys(cur.Scripts))
		scripts := map[string]string{}
		for _, n := range names {
			scripts[n] = trunc(cur.Scripts[n], 300)
		}
		if added {
			out = append(out, mk(RuleInstallScriptAdded, scan.SeverityHigh, true,
				fmt.Sprintf("%s adds an install script (%s) that %s did not have: it runs on every install", label, strings.Join(names, ", "), prev.Version),
				map[string]any{"scripts": scripts, "previous_version": prev.Version}))
		} else {
			out = append(out, mk(RuleInstallScriptAdded, scan.SeverityMedium, false,
				fmt.Sprintf("%s changes its install script (%s) compared with %s", label, strings.Join(names, ", "), prev.Version),
				map[string]any{"scripts": scripts, "previous_version": prev.Version, "changed": true}))
		}
	}
	if cfg.Provenance && prev.Provenance && !cur.Provenance {
		dropped = true
		out = append(out, mk(RuleProvenanceDropped, scan.SeverityHigh, true,
			fmt.Sprintf("%s was published without the build provenance that %s had: it may not come from the project's CI", label, prev.Version),
			map[string]any{"previous_version": prev.Version}))
	}
	if cfg.Publisher && cur.Publisher != "" {
		var earlier []string
		for _, v := range f.releases[k] {
			if v.Published.Before(cur.Published) && v.Publisher != "" && !slices.Contains(earlier, v.Publisher) {
				earlier = append(earlier, v.Publisher)
			}
		}
		if len(earlier) > 0 && !slices.Contains(earlier, cur.Publisher) {
			sort.Strings(earlier)
			sev, block := scan.SeverityMedium, false
			if added || dropped { // a new account plus new install-time code or lost provenance is the hijack pattern
				sev, block = scan.SeverityHigh, true
			}
			out = append(out, mk(RulePublisherChanged, sev, block,
				fmt.Sprintf("%s was published by %q, who never published %s before", label, cur.Publisher, p.GetName()),
				map[string]any{"publisher": cur.Publisher, "previous_publishers": earlier}))
		}
	}
	return out
}
