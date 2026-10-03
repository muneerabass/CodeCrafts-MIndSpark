package enrich_test

import (
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/feeds/feedstest"
	"github.com/safedep/vet/pkg/models"
)

// TestLive syncs real feeds into a throwaway Postgres and enriches real
// packages. Opt in: DEPGUARD_LIVE=1 [DEPGUARD_LIVE_ECOSYSTEMS=Packagist,RubyGems].
func TestLive(t *testing.T) {
	if os.Getenv("DEPGUARD_LIVE") == "" {
		t.Skip("set DEPGUARD_LIVE=1 to sync from the live feeds")
	}
	ecos := []string{"Packagist", "RubyGems"}
	if v := os.Getenv("DEPGUARD_LIVE_ECOSYSTEMS"); v != "" {
		ecos = strings.Split(v, ",")
	}
	pool := feedstest.Postgres(t)
	ctx := context.Background()
	s := feeds.New(pool, feeds.Options{})
	n := func(q string, args ...any) (c int) {
		if err := pool.QueryRow(ctx, q, args...).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, eco := range ecos {
		start := time.Now()
		if err := s.SyncOSV(ctx, eco); err != nil {
			t.Fatal(err)
		}
		boot := time.Since(start)
		start = time.Now()
		if err := s.SyncOSV(ctx, eco); err != nil {
			t.Fatal(err)
		}
		t.Logf("osv %s: bootstrap %s, incremental %s; advisories=%d (malware=%d withdrawn=%d) affected=%d aliases=%d",
			eco, boot.Round(time.Millisecond), time.Since(start).Round(time.Millisecond),
			n(`SELECT count(*) FROM advisory WHERE source=$1`, eco),
			n(`SELECT count(*) FROM advisory WHERE source=$1 AND is_malware`, eco),
			n(`SELECT count(*) FROM advisory WHERE source=$1 AND withdrawn IS NOT NULL`, eco),
			n(`SELECT count(*) FROM affected af JOIN advisory a ON a.id=af.advisory_id WHERE a.source=$1`, eco),
			n(`SELECT count(*) FROM advisory_alias al JOIN advisory a ON a.id=al.advisory_id WHERE a.source=$1`, eco))
	}
	for name, fn := range map[string]func(context.Context) error{"kev": s.SyncKEV, "epss": s.SyncEPSS} {
		start := time.Now()
		if err := fn(ctx); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %s", name, time.Since(start).Round(time.Millisecond))
	}
	t.Logf("cve_score: kev=%d epss=%d", n(`SELECT count(*) FROM cve_score WHERE kev`), n(`SELECT count(*) FROM cve_score WHERE epss IS NOT NULL`))
	risks, _ := pool.Query(ctx, `SELECT risk, count(*) FROM advisory GROUP BY 1 ORDER BY 1`)
	for risks.Next() {
		var r string
		var c int
		risks.Scan(&r, &c)
		t.Logf("risk %s: %d", r, c)
	}
	risks.Close()

	pkgs := []*models.Package{
		pkg(models.EcosystemRubyGems, "actionpack", "5.0.0"),
		pkg(models.EcosystemRubyGems, "nokogiri", "1.10.0"),
		pkg(models.EcosystemPackagist, "laravel/framework", "5.5.0"),
		pkg(models.EcosystemNpm, "lodash", "4.17.15"),
	}
	start := time.Now()
	if err := enrich.New(pool, enrich.Options{}).Enrich(ctx, pkgs); err != nil {
		t.Fatal(err)
	}
	t.Logf("enrich %d pkgs: %s", len(pkgs), time.Since(start).Round(time.Millisecond))
	for _, p := range pkgs {
		ms := enrich.Matches(p)
		byRisk := map[string]int{}
		for _, m := range ms {
			byRisk[m.Risk]++
		}
		var lic []string
		for _, l := range *p.Insights.Licenses {
			lic = append(lic, string(l))
		}
		var proj string
		if p.Insights.Projects != nil {
			pr := (*p.Insights.Projects)[0]
			proj = *pr.Name
			if pr.Stars != nil {
				proj += " stars=" + strconv.Itoa(*pr.Stars)
			}
		}
		var score float32
		if p.Insights.Scorecard != nil {
			score = *p.Insights.Scorecard.Content.Score
		}
		t.Logf("%s@%s: %d vulns %v licenses=%v project=%q scorecard=%.1f", p.Name, p.Version, len(ms), byRisk, lic, proj, score)
		if slices.Contains(ecos, enrich.OSVEcosystem(p)) && len(ms) == 0 {
			t.Errorf("%s@%s: expected known vulnerabilities", p.Name, p.Version)
		}
	}
}
