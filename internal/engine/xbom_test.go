package engine

import (
	"log/slog"
	"slices"
	"testing"
)

func TestAIUsage(t *testing.T) {
	src := "import anthropic\n\n\ndef main():\n    client = anthropic.Anthropic()\n    return client\n"
	got := aiUsage([]file{{Path: "svc/app.py", Data: []byte(src)}}, slog.Default())
	if !slices.Contains(got, "Anthropic API - AI client in svc/app.py:5") {
		t.Fatalf("got %v", got)
	}
}
