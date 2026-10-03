// Package enrich fills vet packages' Insights from depguard's local feed
// mirror (OSV advisories synced by internal/feeds) plus deps.dev and OpenSSF
// Scorecard metadata, cached in package_meta / scorecard for 7 days.
//
//	e := enrich.New(pool, enrich.Options{
//		DisableDepsDev:   os.Getenv("DEPSDEV_DISABLED") != "",
//		DisableScorecard: os.Getenv("SCORECARD_DISABLED") != "",
//	})
//	err := e.Enrich(ctx, pkgs) // fails only on DB errors; network errors are logged
//	for _, m := range enrich.Matches(pkg) {
//		// persist component_vulnerabilities(component, m.AdvisoryID, m.Risk)
//	}
//
// pkg.Insights.Vulnerabilities gets one entry per matched, non-withdrawn
// advisory with a single CVSS_V3-typed severity whose Risk is advisory.risk
// (MAL-* = CRITICAL, UNKNOWN when unscored). vet's CEL evaluator buckets
// vulns.critical/high/medium/low from that Risk. Matches reads the same data
// back, so what the policy saw is exactly what gets persisted.
package enrich

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/feeds"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

// Options configures an Enricher. Zero values use public endpoints.
type Options struct {
	DepsDevURL       string        // default https://api.deps.dev
	ScorecardURL     string        // default https://api.scorecard.dev
	DisableDepsDev   bool          // no deps.dev calls (cached rows are still used)
	DisableScorecard bool          // no Scorecard calls (cached rows are still used)
	HTTPClient       *http.Client  // default: 10s timeout
	Concurrency      int           // parallel HTTP requests, default 8
	CacheTTL         time.Duration // default 7 days
	Logger           *slog.Logger
}

// Enricher fills vet package insights. Safe for concurrent use.
type Enricher struct {
	pool *pgxpool.Pool
	o    Options
}

// New returns an Enricher with defaults filled in.
func New(pool *pgxpool.Pool, o Options) *Enricher {
	if o.DepsDevURL == "" {
		o.DepsDevURL = "https://api.deps.dev"
	}
	if o.ScorecardURL == "" {
		o.ScorecardURL = "https://api.scorecard.dev"
	}
	o.DepsDevURL, o.ScorecardURL = strings.TrimRight(o.DepsDevURL, "/"), strings.TrimRight(o.ScorecardURL, "/")
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 8
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = 7 * 24 * time.Hour
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Enricher{pool: pool, o: o}
}

// Match is one advisory matched to a package (a component_vulnerabilities row).
type Match struct {
	AdvisoryID string
	Risk       string // CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
	Summary    string
	Aliases    []string
	Malware    bool // MAL-* advisory
	// FixedIn is the lowest OSV "fixed" version above the installed one in
	// the matched affected range ("" if none).
	FixedIn string
}

// fixedPrefix marks FixedIn inside PackageVulnerability.Related: insights
// have no field for it and vet's policy evaluator ignores Related.
const fixedPrefix = "depguard:fixed-in="

// Matches returns the advisories Enrich attached to pkg.
func Matches(pkg *models.Package) []Match {
	if pkg.Insights == nil || pkg.Insights.Vulnerabilities == nil {
		return nil
	}
	var out []Match
	for _, v := range *pkg.Insights.Vulnerabilities {
		m := Match{AdvisoryID: deref(v.Id), Summary: deref(v.Summary), Risk: "UNKNOWN"}
		if v.Aliases != nil {
			m.Aliases = *v.Aliases
		}
		if v.Severities != nil && len(*v.Severities) > 0 && (*v.Severities)[0].Risk != nil {
			m.Risk = string(*(*v.Severities)[0].Risk)
		}
		m.Malware = strings.HasPrefix(m.AdvisoryID, "MAL-")
		if v.Related != nil {
			for _, r := range *v.Related {
				if f, ok := strings.CutPrefix(r, fixedPrefix); ok {
					m.FixedIn = f
				}
			}
		}
		out = append(out, m)
	}
	return out
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func ptr[T any](v T) *T { return &v }

// vet ecosystem (models.Ecosystem*) or lockfile ecosystem → OSV ecosystem.
var osvEcosystems = map[string]string{
	models.EcosystemNpm: "npm", models.EcosystemPyPI: "PyPI", models.EcosystemGo: "Go",
	models.EcosystemMaven: "Maven", models.EcosystemCargo: "crates.io", "crates.io": "crates.io",
	models.EcosystemRubyGems: "RubyGems", models.EcosystemPackagist: "Packagist",
	models.EcosystemGitHubActions: "GitHub Actions", "GitHub Actions": "GitHub Actions",
	models.EcosystemNuGet: "NuGet", models.EcosystemHex: "Hex", models.EcosystemPub: "Pub",
}

// OSVEcosystem maps a vet package to its OSV ecosystem name, "" if unsupported.
func OSVEcosystem(pkg *models.Package) string {
	if e, ok := osvEcosystems[string(pkg.Ecosystem)]; ok {
		return e
	}
	if pkg.Manifest != nil {
		return osvEcosystems[pkg.Manifest.Ecosystem]
	}
	return ""
}

type key struct{ eco, name string }

type item struct {
	pkg *models.Package
	key key
}

// Enrich replaces pkg.Insights for every package. It returns an error only
// if the advisory query fails; deps.dev / Scorecard problems are logged.
func (e *Enricher) Enrich(ctx context.Context, pkgs []*models.Package) error {
	var items []item
	for _, p := range pkgs {
		if eco := OSVEcosystem(p); eco != "" {
			items = append(items, item{p, key{eco, feeds.NormalizeName(eco, p.GetName())}})
		}
	}
	vulns, err := e.vulns(ctx, items)
	if err != nil {
		return err
	}
	meta := e.meta(ctx, items)
	var repos []string
	for _, m := range meta {
		if m.repo != "" {
			repos = append(repos, m.repo)
		}
	}
	cards := e.scorecards(ctx, repos)

	for _, p := range pkgs {
		vs := vulns[p]
		if vs == nil {
			vs = []insightapi.PackageVulnerability{}
		}
		vetEco := string(p.Ecosystem)
		if vetEco == "" && p.Manifest != nil {
			vetEco = p.Manifest.Ecosystem
		}
		ins := &insightapi.PackageVersionInsight{
			PackageVersion:  &insightapi.PackageVersion{Ecosystem: vetEco, Name: p.GetName(), Version: p.GetVersion()},
			Vulnerabilities: &vs,
			Licenses:        &[]insightapi.License{},
		}
		eco := OSVEcosystem(p)
		if m := meta[metaKey{key{eco, feeds.NormalizeName(eco, p.GetName())}, p.GetVersion()}]; m != nil {
			lic := make([]insightapi.License, len(m.licenses))
			for i, l := range m.licenses {
				lic[i] = insightapi.License(l)
			}
			ins.Licenses = &lic
			if m.repo != "" {
				ins.Projects = &[]insightapi.PackageProjectInfo{{
					Name: ptr(m.repo), DisplayName: ptr(m.repo), Link: ptr("https://" + m.repo),
					Stars: m.stars, Forks: m.forks, Type: ptr("GITHUB"),
				}}
				ins.Scorecard = cards[m.repo]
			}
		}
		p.Insights = ins
	}
	return nil
}

// vulns matches items against the affected table, 500 package keys per query.
func (e *Enricher) vulns(ctx context.Context, items []item) (map[*models.Package][]insightapi.PackageVulnerability, error) {
	byKey := map[key][]*models.Package{}
	var keys []key
	for _, it := range items {
		if _, ok := byKey[it.key]; !ok {
			keys = append(keys, it.key)
		}
		byKey[it.key] = append(byKey[it.key], it.pkg)
	}
	out := map[*models.Package][]insightapi.PackageVulnerability{}
	seen := map[*models.Package]map[string]bool{}
	for i := 0; i < len(keys); i += 500 {
		var ecos, names []string
		for _, k := range keys[i:min(i+500, len(keys))] {
			ecos, names = append(ecos, k.eco), append(names, k.name)
		}
		rows, err := e.pool.Query(ctx, `
			SELECT af.ecosystem, af.name_norm, af.versions, af.ranges, ad.id, coalesce(ad.summary, ''), ad.severity, ad.risk,
			  coalesce((SELECT array_agg(alias ORDER BY alias) FROM advisory_alias WHERE advisory_id = ad.id), '{}')
			FROM affected af JOIN advisory ad ON ad.id = af.advisory_id
			WHERE ad.withdrawn IS NULL
			  AND (af.ecosystem, af.name_norm) IN (SELECT * FROM unnest($1::text[], $2::text[]))`, ecos, names)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var (
				k                   key
				versions, aliases   []string
				rangesJSON, sevJSON []byte
				id, summary, risk   string
				ranges              []osvRange
				sev                 []feeds.Severity
			)
			if err := rows.Scan(&k.eco, &k.name, &versions, &rangesJSON, &id, &summary, &sevJSON, &risk, &aliases); err != nil {
				rows.Close()
				return nil, err
			}
			_ = json.Unmarshal(rangesJSON, &ranges)
			_ = json.Unmarshal(sevJSON, &sev)
			for _, p := range byKey[k] {
				if seen[p][id] || !affects(k.eco, p.GetVersion(), versions, ranges) {
					continue
				}
				if seen[p] == nil {
					seen[p] = map[string]bool{}
				}
				seen[p][id] = true
				v := toVuln(id, summary, risk, aliases, sev)
				if f := fixedIn(k.eco, p.GetVersion(), ranges); f != "" {
					v.Related = &[]string{fixedPrefix + f}
				}
				out[p] = append(out[p], v)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	for _, vs := range out {
		sort.Slice(vs, func(i, j int) bool { return *vs[i].Id < *vs[j].Id })
	}
	return out, nil
}

func toVuln(id, summary, risk string, aliases []string, sev []feeds.Severity) insightapi.PackageVulnerability {
	r := insightapi.PackageVulnerabilitySeveritiesRisk(risk)
	switch r {
	case insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL, insightapi.PackageVulnerabilitySeveritiesRiskHIGH,
		insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM, insightapi.PackageVulnerabilitySeveritiesRiskLOW:
	default:
		r = insightapi.PackageVulnerabilitySeveritiesRiskUNKNOWN
	}
	_, vector := feeds.BestCVSS(sev)
	sevs := []struct {
		Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
		Score *string                                        `json:"score,omitempty"`
		Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
	}{{Risk: &r, Type: ptr(insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3)}}
	if vector != "" {
		sevs[0].Score = &vector
	}
	v := insightapi.PackageVulnerability{Id: ptr(id), Aliases: &aliases, Severities: &sevs}
	if summary != "" {
		v.Summary = &summary
	}
	return v
}
