// Package prsettings is the team's pull request configuration
// (tenant_settings.pr_settings): what the bot comment contains, labels, and
// the AI security review.
package prsettings

import (
	"encoding/json"
	"fmt"
)

// Sections that can be turned off in the comment.
var Sections = []string{"fix_commands", "code_review", "vulnerabilities", "licenses", "suspicious", "run_config"}

type Settings struct {
	// CommentMode: always = comment on every PR; issues = only when there are
	// findings (and to say they were fixed); never = check run only.
	CommentMode           string          `json:"comment_mode"`
	Sections              map[string]bool `json:"sections"`
	RequestChangesOnBlock bool            `json:"request_changes_on_block"`
	MentionAuthorOnBlock  bool            `json:"mention_author_on_block"`
	Header                string          `json:"header"`
	Footer                string          `json:"footer"`
	Labels                struct {
		Enabled bool   `json:"enabled"` // apply depguard labels on GitHub
		Prefix  string `json:"prefix"`
	} `json:"labels"`
	AIReview struct {
		Enabled   bool `json:"enabled"`
		MaxDiffKB int  `json:"max_diff_kb"`
	} `json:"ai_review"`
}

// Default is the configuration when nothing is stored.
func Default() Settings {
	s := Settings{CommentMode: "always", MentionAuthorOnBlock: true, Sections: map[string]bool{}}
	for _, k := range Sections {
		s.Sections[k] = true
	}
	s.Labels.Enabled, s.Labels.Prefix = true, "depguard:"
	s.AIReview.Enabled, s.AIReview.MaxDiffKB = true, 200
	return s
}

// Parse reads stored JSON over the defaults (missing keys keep defaults).
func Parse(raw []byte) Settings {
	s := Default()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &s)
	}
	if s.Sections == nil {
		s.Sections = Default().Sections
	}
	for _, k := range Sections {
		if _, ok := s.Sections[k]; !ok {
			s.Sections[k] = true
		}
	}
	if s.Labels.Prefix == "" {
		s.Labels.Prefix = "depguard:"
	}
	if s.AIReview.MaxDiffKB <= 0 {
		s.AIReview.MaxDiffKB = 200
	}
	return s
}

// Validate checks a settings update from the dashboard.
func (s Settings) Validate() error {
	switch s.CommentMode {
	case "always", "issues", "never":
	default:
		return fmt.Errorf("comment_mode must be always, issues or never")
	}
	if len(s.Header) > 2000 || len(s.Footer) > 2000 {
		return fmt.Errorf("header and footer are limited to 2000 characters")
	}
	if len(s.Labels.Prefix) > 20 {
		return fmt.Errorf("label prefix is limited to 20 characters")
	}
	if s.AIReview.MaxDiffKB < 10 || s.AIReview.MaxDiffKB > 1000 {
		return fmt.Errorf("ai_review.max_diff_kb must be between 10 and 1000")
	}
	for k := range s.Sections {
		known := false
		for _, x := range Sections {
			known = known || k == x
		}
		if !known {
			return fmt.Errorf("unknown comment section %q", k)
		}
	}
	return nil
}
