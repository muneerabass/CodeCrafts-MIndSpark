// Package health scores how trustworthy an open-source package looks (0-10)
// from cached metadata: OpenSSF Scorecard, release recency, popularity, a
// source repository, deprecation and age. Missing data is left out of the
// score instead of counting against the package.
package health

import (
	"fmt"
	"math"
	"time"
)

// Input is what is known about a package version; nil means unknown.
type Input struct {
	Scorecard      *float64   // OpenSSF Scorecard 0-10 of the source repo
	LastRelease    *time.Time // newest release of the package
	FirstPublished *time.Time // first release ever
	Stars          *int       // source repo stars
	HasRepo        *bool      // a source repository is known
	Deprecated     *bool      // the maintainers deprecated it
	Malicious      bool
	Now            time.Time
}

// Factor is one part of the score.
type Factor struct {
	Key    string   `json:"key"`
	Label  string   `json:"label"`
	Weight float64  `json:"weight"` // share of the score, before unknowns are dropped
	Value  *float64 `json:"value"`  // 0-1; nil = unknown
	Detail string   `json:"detail"`
}

// Result is the score with its factors; Score is nil when nothing is known.
type Result struct {
	Score   *float64 `json:"score"` // 0-10, one decimal
	Level   string   `json:"level"` // good | fair | poor | unknown | malicious
	Factors []Factor `json:"factors"`
}

func v(x float64) *float64 { return &x }

// Score computes the health of a package.
func Score(in Input) Result {
	months := func(t time.Time) float64 { return in.Now.Sub(t).Hours() / 24 / 30.44 }
	fs := []Factor{
		{Key: "scorecard", Label: "OpenSSF Scorecard", Weight: 40},
		{Key: "recency", Label: "Recent releases", Weight: 20},
		{Key: "popularity", Label: "Popularity", Weight: 15},
		{Key: "repo", Label: "Source repository", Weight: 10},
		{Key: "deprecated", Label: "Not deprecated", Weight: 10},
		{Key: "age", Label: "Established", Weight: 5},
	}
	if in.Scorecard != nil {
		fs[0].Value, fs[0].Detail = v(math.Max(0, math.Min(10, *in.Scorecard))/10), fmt.Sprintf("%.1f / 10", *in.Scorecard)
	} else {
		fs[0].Detail = "No Scorecard yet (counted as neutral)"
	}
	if in.LastRelease != nil {
		m := months(*in.LastRelease)
		val := 0.0
		switch {
		case m <= 6:
			val = 1
		case m <= 12:
			val = 0.8
		case m <= 24:
			val = 0.5
		case m <= 48:
			val = 0.2
		}
		fs[1].Value, fs[1].Detail = v(val), "Last release "+ago(m)
	} else {
		fs[1].Detail = "Release history unknown"
	}
	if in.Stars != nil {
		fs[2].Value, fs[2].Detail = v(math.Min(1, math.Log10(float64(*in.Stars)+1)/4)), fmt.Sprintf("%d stars", *in.Stars) // 10k stars = full marks
	} else {
		fs[2].Detail = "Popularity unknown"
	}
	if in.HasRepo != nil {
		fs[3].Value, fs[3].Detail = b2f(*in.HasRepo), map[bool]string{true: "Linked to its source code", false: "No source repository published"}[*in.HasRepo]
	}
	if in.Deprecated != nil {
		fs[4].Value, fs[4].Detail = b2f(!*in.Deprecated), map[bool]string{true: "Deprecated by its maintainers", false: "Not deprecated"}[*in.Deprecated]
	}
	if in.FirstPublished != nil {
		fs[5].Value, fs[5].Detail = b2f(months(*in.FirstPublished) >= 3), "First published "+ago(months(*in.FirstPublished))
	}
	r := Result{Factors: fs, Level: "unknown"}
	if in.Malicious {
		r.Score, r.Level = v(0), "malicious"
		return r
	}
	var sum, w, known float64
	for _, f := range fs {
		switch {
		case f.Value != nil:
			sum += *f.Value * f.Weight
			w += f.Weight
			known += f.Weight
		case f.Key == "scorecard":
			// Most small packages have no Scorecard: count it as neutral so a
			// handful of easy signals (has a repo, not deprecated) can't make an
			// obscure package look excellent.
			sum += 0.5 * f.Weight
			w += f.Weight
		}
	}
	if known < 25 { // too little data to judge
		return r
	}
	s := math.Round(sum/w*100) / 10
	r.Score = &s
	switch {
	case s >= 7:
		r.Level = "good"
	case s >= 4:
		r.Level = "fair"
	default:
		r.Level = "poor"
	}
	return r
}

func b2f(b bool) *float64 {
	if b {
		return v(1)
	}
	return v(0)
}

func ago(months float64) string {
	switch {
	case months < 1:
		return "this month"
	case months < 2:
		return "1 month ago"
	case months < 12:
		return fmt.Sprintf("%d months ago", int(months))
	case months < 24:
		return "1 year ago"
	}
	return fmt.Sprintf("%d years ago", int(months/12))
}
