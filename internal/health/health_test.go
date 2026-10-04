package health

import (
	"testing"
	"time"
)

func TestScore(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	at := func(months int) *time.Time { x := now.AddDate(0, -months, 0); return &x }
	f := func(x float64) *float64 { return &x }
	i := func(x int) *int { return &x }
	b := func(x bool) *bool { return &x }
	cases := []struct {
		name  string
		in    Input
		score float64 // -1 = unknown
		level string
	}{
		{"healthy", Input{Scorecard: f(8), LastRelease: at(2), Stars: i(20000), HasRepo: b(true), Deprecated: b(false), FirstPublished: at(60)}, 9.2, "good"},
		{"abandoned", Input{Scorecard: f(2), LastRelease: at(70), Stars: i(30), HasRepo: b(true), Deprecated: b(true), FirstPublished: at(100)}, 2.9, "poor"},
		{"new, no repo", Input{LastRelease: at(0), Stars: nil, HasRepo: b(false), Deprecated: b(false), FirstPublished: at(0)}, 5.9, "fair"},
		{"unknowns dropped", Input{Scorecard: f(10), LastRelease: at(1)}, 10, "good"},
		{"too little data", Input{Deprecated: b(false)}, -1, "unknown"},
		{"obscure, no scorecard", Input{LastRelease: at(1), Stars: i(1), HasRepo: b(true), Deprecated: b(false), FirstPublished: at(60)}, 6.6, "fair"},
		{"malicious", Input{Scorecard: f(9), Malicious: true}, 0, "malicious"},
	}
	for _, c := range cases {
		c.in.Now = now
		r := Score(c.in)
		got := -1.0
		if r.Score != nil {
			got = *r.Score
		}
		if got != c.score || r.Level != c.level || len(r.Factors) != 6 {
			t.Errorf("%s: score %v level %s", c.name, got, r.Level)
		}
	}
}
