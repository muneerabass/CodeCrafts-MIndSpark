// Package prrank scores how urgently a pull request must be fixed, from its
// dependency review and code review. Pure and deterministic.
package prrank

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/render"
)

// Levels, most urgent first.
const (
	Critical = "critical"
	High     = "high"
	Medium   = "medium"
	Low      = "low"
	Clean    = "clean"
	Pending  = "pending"
)

// Reason is why a PR is urgent, shown in the dashboard and the comment.
type Reason struct {
	Kind  string `json:"kind"` // malware | vulnerability | policy | license | suspicious | code
	Text  string `json:"text"`
	Score int    `json:"score"`
}

// Result is a PR's urgency.
type Result struct {
	Score   int      `json:"score"` // 0-100
	Level   string   `json:"level"`
	Reasons []Reason `json:"reasons"` // top 3
}

// Input is everything the score depends on.
type Input struct {
	Summary  render.PRSummary
	Review   render.PRReview
	Open     bool
	OpenedAt time.Time
	Now      time.Time
}

func depScore(f render.FixItem) int {
	switch {
	case f.Kind == "malware":
		return 100
	case f.Kind == "vulnerability":
		switch f.Severity {
		case "critical":
			if f.KEV {
				return 95
			}
			return 85
		case "high":
			if f.Direct || f.KEV {
				return 75
			}
			return 65
		case "medium":
			return 35
		}
		return 15
	case f.Blocking:
		return 60
	case f.Severity == "medium" || f.Severity == "high":
		return 35
	}
	return 15
}

func codeScore(f render.ReviewFinding) int {
	if f.Category == "secrets" && f.Severity == "critical" {
		return 95 // a live credential is exploitable as soon as the branch is pushed
	}
	switch f.Severity {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 35
	}
	return 15
}

// Rank computes the urgency.
func Rank(in Input) Result {
	var rs []Reason
	for _, f := range in.Summary.Fixes {
		rs = append(rs, Reason{Kind: f.Kind, Text: plain(f.Title), Score: depScore(f)})
	}
	for _, f := range in.Review.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		src := ""
		if f.Source == "ai" {
			src = "AI: "
		}
		kind := "code"
		if f.Category == "secrets" {
			kind = "secret"
		}
		rs = append(rs, Reason{Kind: kind, Text: fmt.Sprintf("%s%s in %s", src, f.Title, loc), Score: codeScore(f)})
	}
	slices.SortStableFunc(rs, func(a, b Reason) int { return b.Score - a.Score })
	res := Result{Level: Clean}
	if len(rs) == 0 {
		return res
	}
	score, serious := rs[0].Score, 0
	for _, r := range rs {
		if r.Score >= 60 {
			serious++
		}
	}
	if serious >= 2 {
		score += 5
	}
	if in.Open && rs[0].Score >= 60 && !in.OpenedAt.IsZero() {
		days := int(in.Now.Sub(in.OpenedAt).Hours() / 24)
		score += min(10, max(0, days)) // risky PRs left open get more urgent
	}
	res.Score = min(100, score)
	switch {
	case res.Score >= 85:
		res.Level = Critical
	case res.Score >= 60:
		res.Level = High
	case res.Score >= 30:
		res.Level = Medium
	default:
		res.Level = Low
	}
	// Top reasons, one per distinct text.
	seen := map[string]bool{}
	for _, r := range rs {
		if len(res.Reasons) == 3 {
			break
		}
		if !seen[r.Text] {
			seen[r.Text] = true
			res.Reasons = append(res.Reasons, r)
		}
	}
	return res
}

// plain strips markdown code marks and escapes for display.
func plain(s string) string {
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "@‍", "@")
	for _, c := range []string{`\_`, `\*`, `\[`, `\]`, `\(`, `\)`, `\#`, `\!`, `\|`, `\~`, `\{`, `\}`, `\\`} {
		s = strings.ReplaceAll(s, c, c[1:])
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "&lt;", "<"), "&gt;", ">")
}
