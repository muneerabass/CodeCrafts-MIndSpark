package render

import (
	"strings"
	"testing"
)

func TestPRCommentSecretsPill(t *testing.T) {
	in := PRCommentInput{PublicURL: "https://app", ProjectID: "p", PRNumber: 1, Summary: PRSummary{Checks: map[string]string{}},
		Settings: CommentSettings{Sections: map[string]bool{}}}
	if b := PRComment(in); !strings.Contains(b, `alt="SECRETS: pass"`) {
		t.Fatalf("no secrets pill:\n%s", b)
	}
	in.Review = PRReview{Findings: []ReviewFinding{{Source: "rules", File: ".env", Line: 2, Severity: "high", Category: "secrets", Title: "Hard-coded password or secret"}}}
	if b := PRComment(in); !strings.Contains(b, `alt="SECRETS: warn"`) {
		t.Fatal("password should warn")
	}
	in.Review.Findings = append(in.Review.Findings, ReviewFinding{Source: "rules", File: ".env", Line: 3, Severity: "critical", Category: "secrets", Title: "AWS access key committed"})
	if b := PRComment(in); !strings.Contains(b, `alt="SECRETS: fail"`) || !strings.Contains(b, `src="https://app/badges/secrets-fail.svg"`) {
		t.Fatal("key should fail")
	}
}
