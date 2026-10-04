package suspicious

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/registry"
	"github.com/depguard/depguard/internal/scan"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/safedep/vet/pkg/models"
)

// Rule names (scan.Finding.Rule / policy_violations.rule_name).
const (
	RuleTyposquat        = "typosquat"
	RuleDeprecated       = "deprecated"
	RuleUnmaintained     = "unmaintained"
	RuleNewPackage       = "new-package"
	RuleNoSourceRepo     = "no-source-repo"
	RuleUnusualBehaviour = "unusual-behaviour" // written by the guarddog worker
)

const (
	popularStars = 1000 // packages with this many repo stars are never typosquats
	lowStars     = 50   // guarddog priority: below this the repo counts as obscure
	newPackage   = 30 * 24 * time.Hour
)

// Config selects rules; Blocking holds rule names that fail the check.
type Config struct {
	Typosquat, Unmaintained, Deprecated, NewPackage, NoRepo, UnusualBehaviour bool
	UnmaintainedMonths                                                        int
	Blocking                                                                  map[string]bool
	Fresh                                                                     scan.FreshPreset // brand-new release rules
}

// ConfigFromPolicy maps presets.suspicious (nil = scan.DefaultSuspicious()).
func ConfigFromPolicy(p scan.PolicyConfig) Config {
	s := scan.DefaultSuspicious()
	if p.Presets != nil && p.Presets.Suspicious != nil {
		s = *p.Presets.Suspicious
	}
	c := Config{Typosquat: s.Typosquat, Unmaintained: s.Unmaintained, Deprecated: s.Deprecated, NewPackage: s.NewPackage,
		NoRepo: s.NoSourceRepo, UnusualBehaviour: s.UnusualBehaviour, UnmaintainedMonths: s.UnmaintainedMonths,
		Blocking: map[string]bool{}, Fresh: p.FreshRules()}
	if c.UnmaintainedMonths <= 0 {
		c.UnmaintainedMonths = 24
	}
	for _, r := range s.Blocking {
		c.Blocking[r] = true
	}
	return c
}

type checker struct {
	pool *pgxpool.Pool
	e    *enrich.Enricher
	reg  *registry.Client
	cfg  Config
	now  func() time.Time
}

// New returns the suspicious-package checker. pool (package_meta publish
// dates) and e (deps.dev package data) may be nil: their rules are skipped.
func New(pool *pgxpool.Pool, e *enrich.Enricher, cfg Config) scan.Checker {
	return &checker{pool: pool, e: e, reg: &registry.Client{}, cfg: cfg, now: time.Now}
}

func (c *checker) Name() string { return "suspicious" }

// facts is what the rules need beyond pkg.Insights.
type facts struct {
	latest        map[*models.Package]*enrich.Latest
	published     map[*models.Package]time.Time
	releases      map[registry.Pkg][]registry.Version // npm/PyPI release history
	securityFixes map[string]bool                     // "eco/name@version" that fix an advisory
}

// Check never fails: data that can't be fetched just disables its rule.
func (c *checker) Check(ctx context.Context, in scan.CheckInput) ([]scan.Finding, error) {
	f := facts{latest: map[*models.Package]*enrich.Latest{}, published: map[*models.Package]time.Time{}}
	if c.e != nil && (c.cfg.Deprecated || c.cfg.Unmaintained) {
		f.latest = c.e.PackagesLatest(ctx, in.Packages)
	}
	if c.pool != nil && (c.cfg.NewPackage || freshOn(c.cfg.Fresh)) {
		var err error
		if f.published, err = publishedAt(ctx, c.pool, in.Packages); err != nil {
			slog.Warn("suspicious: package_meta read failed", "err", err)
		}
	}
	if c.pool != nil && freshOn(c.cfg.Fresh) {
		c.loadFresh(ctx, in.Packages, &f)
	}
	var out []scan.Finding
	for _, p := range in.Packages {
		out = append(out, c.evaluate(p, f)...)
		out = append(out, c.evaluateFresh(p, f)...)
	}
	return out, nil
}

func (c *checker) finding(rule, sev, summary string, p *models.Package, details map[string]any) scan.Finding {
	return scan.Finding{Rule: rule, Category: scan.CategorySuspicious, Severity: sev, Blocking: c.cfg.Blocking[rule],
		Summary: summary, Details: details, Package: p}
}

func (c *checker) evaluate(p *models.Package, f facts) []scan.Finding {
	var out []scan.Finding
	eco := enrich.OSVEcosystem(p)
	repo, stars := repoInfo(p)
	if c.cfg.Typosquat && stars < popularStars {
		if sim, tech := Typosquat(eco, p.GetName()); sim != "" {
			out = append(out, c.finding(RuleTyposquat, scan.SeverityHigh,
				fmt.Sprintf("Name %q closely resembles the popular package %q (possible typosquat)", p.GetName(), sim), p,
				map[string]any{"similar_to": sim, "technique": tech}))
		}
	}
	l := f.latest[p]
	if c.cfg.Deprecated && l.VersionDeprecated(p.GetVersion()) {
		summary := fmt.Sprintf("%s@%s is deprecated", p.GetName(), p.GetVersion())
		if l.Deprecated {
			summary = fmt.Sprintf("Package %s is deprecated", p.GetName())
		}
		if l.DeprecatedReason != "" {
			summary += ": " + l.DeprecatedReason
		}
		out = append(out, c.finding(RuleDeprecated, scan.SeverityMedium, summary, p,
			map[string]any{"reason": l.DeprecatedReason, "default_version": l.DefaultVersion}))
	}
	if c.cfg.Unmaintained && l != nil && l.LatestPublished != nil &&
		l.LatestPublished.Before(c.now().AddDate(0, -c.cfg.UnmaintainedMonths, 0)) {
		score, hasScore := maintainedScore(p)
		months := int(c.now().Sub(*l.LatestPublished).Hours() / 24 / 30)
		inactiveRepo := hasScore && score <= 1
		noRepo := repo == "" && p.Insights != nil
		// Require evidence of abandonment: an inactive repo (Scorecard), or no repo
		// at all plus a very stale release. Finished, stable libraries with an
		// active repo are not flagged; missing data alone is not evidence.
		if inactiveRepo || (noRepo && months >= 48) {
			d := map[string]any{"latest_published": l.LatestPublished.UTC().Format(time.RFC3339), "maintained_score": nil}
			if hasScore {
				d["maintained_score"] = score
			}
			sev := scan.SeverityLow
			if inactiveRepo && months >= 48 {
				sev = scan.SeverityMedium
			}
			why := "no recent activity in its source repository"
			if !inactiveRepo {
				why = "no linked source repository"
			}
			out = append(out, c.finding(RuleUnmaintained, sev,
				fmt.Sprintf("No release in %d months (last %s) and %s", months, l.LatestPublished.Format("2006-01-02"), why), p, d))
		}
	}
	// A brand-new package (not a new version of an established one) is the
	// window in which typosquats and malware are most common.
	if c.cfg.NewPackage && l != nil && l.FirstPublished != nil && c.now().Sub(*l.FirstPublished) < newPackage {
		t := *l.FirstPublished
		days := int(math.Max(0, c.now().Sub(t).Hours()/24))
		out = append(out, c.finding(RuleNewPackage, scan.SeverityLow,
			fmt.Sprintf("%s is a new package: first published %d days ago", p.GetName(), days), p,
			map[string]any{"first_published": t.UTC().Format(time.RFC3339), "age_days": days}))
	}
	// Without Insights we don't know; only flag when enrichment ran.
	if c.cfg.NoRepo && repo == "" && p.Insights != nil {
		out = append(out, c.finding(RuleNoSourceRepo, scan.SeverityLow, "No source repository is linked to this package", p, map[string]any{}))
	}
	return out
}

// repoInfo returns the linked source repository and its stars (max over projects).
func repoInfo(p *models.Package) (repo string, stars int) {
	if p.Insights == nil || p.Insights.Projects == nil {
		return "", 0
	}
	for _, pr := range *p.Insights.Projects {
		if pr.Name != nil && repo == "" {
			repo = *pr.Name
		}
		if pr.Stars != nil && *pr.Stars > stars {
			stars = *pr.Stars
		}
	}
	return repo, stars
}

// maintainedScore is the OpenSSF Scorecard "Maintained" check (0-10).
func maintainedScore(p *models.Package) (float32, bool) {
	if p.Insights == nil || p.Insights.Scorecard == nil || p.Insights.Scorecard.Content == nil || p.Insights.Scorecard.Content.Checks == nil {
		return 0, false
	}
	for _, ch := range *p.Insights.Scorecard.Content.Checks {
		if ch.Name != nil && string(*ch.Name) == "Maintained" && ch.Score != nil {
			return *ch.Score, true
		}
	}
	return 0, false
}

// publishedAt reads version publish dates cached in package_meta by Enrich.
func publishedAt(ctx context.Context, pool *pgxpool.Pool, pkgs []*models.Package) (map[*models.Package]time.Time, error) {
	type k struct{ eco, name, version string }
	byKey := map[k][]*models.Package{}
	var ecos, names, vers []string
	for _, p := range pkgs {
		eco := enrich.OSVEcosystem(p)
		if eco == "" {
			continue
		}
		key := k{eco, feeds.NormalizeName(eco, p.GetName()), p.GetVersion()}
		if byKey[key] == nil {
			ecos, names, vers = append(ecos, key.eco), append(names, key.name), append(vers, key.version)
		}
		byKey[key] = append(byKey[key], p)
	}
	out := map[*models.Package]time.Time{}
	if len(ecos) == 0 {
		return out, nil
	}
	rows, err := pool.Query(ctx, `SELECT ecosystem, name_norm, version, published_at FROM package_meta
		WHERE published_at IS NOT NULL AND (ecosystem, name_norm, version) IN (SELECT * FROM unnest($1::text[], $2::text[], $3::text[]))`,
		ecos, names, vers)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var key k
		var t time.Time
		if err := rows.Scan(&key.eco, &key.name, &key.version, &t); err != nil {
			return out, err
		}
		for _, p := range byKey[key] {
			out[p] = t
		}
	}
	return out, rows.Err()
}

// Prioritize orders packages for guarddog analysis: typosquat hits, then
// deprecated or brand-new packages, then packages without a repository or
// with fewer than 50 stars, then the rest (stable within each group).
func Prioritize(pkgs []*models.Package, findings []scan.Finding) []*models.Package {
	rank := map[*models.Package]int{}
	for _, f := range findings {
		r := 3
		switch f.Rule {
		case RuleTyposquat:
			r = 0
		case RuleDeprecated, RuleNewPackage:
			r = 1
		}
		if cur, ok := rank[f.Package]; !ok || r < cur {
			rank[f.Package] = r
		}
	}
	out := slices.Clone(pkgs)
	key := func(p *models.Package) int {
		r, ok := rank[p]
		if ok && r < 2 {
			return r
		}
		if repo, stars := repoInfo(p); repo == "" || stars < lowStars {
			return 2
		}
		return 3
	}
	slices.SortStableFunc(out, func(a, b *models.Package) int { return key(a) - key(b) })
	return out
}
