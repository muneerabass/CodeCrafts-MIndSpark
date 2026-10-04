package prrank

import (
	"testing"
	"time"

	"github.com/depguard/depguard/internal/render"
)

func TestRank(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	fix := func(kind, sev string, blocking, kev, direct bool) render.FixItem {
		return render.FixItem{Kind: kind, Severity: sev, Blocking: blocking, KEV: kev, Direct: direct, Title: "`" + kind + "@" + sev + "` issue"}
	}
	code := func(sev string) render.ReviewFinding {
		return render.ReviewFinding{Source: "ai", File: "api/users.js", Line: 42, Severity: sev, Title: "SQL injection"}
	}
	cases := []struct {
		name  string
		in    Input
		score int
		level string
	}{
		{"clean", Input{}, 0, Clean},
		{"malware", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("malware", "critical", true, false, false)}}}, 100, Critical},
		{"critical kev", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("vulnerability", "critical", true, true, false)}}}, 95, Critical},
		{"high direct", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("vulnerability", "high", true, false, true)}}}, 75, High},
		{"high transitive", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("vulnerability", "high", true, false, false)}}}, 65, High},
		{"medium vuln", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("vulnerability", "medium", false, false, false)}}}, 35, Medium},
		{"blocking policy", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("policy", "high", true, false, false)}}}, 60, High},
		{"warning only", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("suspicious", "low", false, false, false)}}}, 15, Low},
		{"code critical", Input{Review: render.PRReview{Findings: []render.ReviewFinding{code("critical")}}}, 90, Critical},
		{"two serious issues", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("vulnerability", "high", true, false, false)}},
			Review: render.PRReview{Findings: []render.ReviewFinding{code("high")}}}, 75, High},
		{"stale open risky PR", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("policy", "high", true, false, false)}},
			Open: true, OpenedAt: now.Add(-30 * 24 * time.Hour), Now: now}, 70, High},
		{"stale low PR not boosted", Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("suspicious", "low", false, false, false)}},
			Open: true, OpenedAt: now.Add(-30 * 24 * time.Hour), Now: now}, 15, Low},
	}
	for _, c := range cases {
		r := Rank(c.in)
		if r.Score != c.score || r.Level != c.level {
			t.Errorf("%s: score %d level %s, want %d %s", c.name, r.Score, r.Level, c.score, c.level)
		}
	}
	r := Rank(Input{Summary: render.PRSummary{Fixes: []render.FixItem{fix("vulnerability", "high", true, false, false), fix("malware", "critical", true, false, false)}},
		Review: render.PRReview{Findings: []render.ReviewFinding{code("high"), code("low")}}})
	if len(r.Reasons) != 3 || r.Reasons[0].Kind != "malware" || r.Reasons[1].Text != "AI: SQL injection in api/users.js:42" || r.Reasons[0].Text != "malware@critical issue" {
		t.Errorf("reasons %+v", r.Reasons)
	}
}

func TestSecretsRankCritical(t *testing.T) {
	r := Rank(Input{Review: render.PRReview{Findings: []render.ReviewFinding{
		{Source: "rules", File: "config.js", Line: 12, Severity: "critical", Category: "secrets", Title: "AWS access key committed"},
		{Source: "ai", File: "api.js", Line: 3, Severity: "critical", Category: "injection", Title: "SQL injection"},
	}}, Open: true, Now: time.Now(), OpenedAt: time.Now()})
	if r.Level != Critical || r.Score < 95 || r.Reasons[0].Kind != "secret" || r.Reasons[0].Text != "AWS access key committed in config.js:12" {
		t.Fatalf("%+v", r)
	}
}
