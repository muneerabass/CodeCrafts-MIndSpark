package assist

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/llm"
)

func TestRunRedactsSecrets(t *testing.T) {
	tl := Tool{Name: "x", Run: func(context.Context, Env, map[string]any) (any, error) {
		return json.RawMessage(`{"name":".env","fingerprints":[{"name":"K","sha256":"h"}],"findings":[{"title":"t","fingerprint":"f"}],
			"wrapped":{"iv":"i","ciphertext":"c"},"vault_matches":[1]}`), nil
	}}
	out := string(Run(context.Background(), Env{}, tl, nil))
	if out != `{"findings":[{"title":"t"}],"name":".env"}` {
		t.Fatalf("redacted: %s", out)
	}
	list := Tool{Name: "z", Run: func(context.Context, Env, map[string]any) (any, error) {
		items := make([]map[string]string, 400)
		for i := range items {
			items[i] = map[string]string{"name": strings.Repeat("p", 200)}
		}
		return map[string]any{"items": items, "total": 400}, nil
	}}
	var shrunk struct {
		Items      []any
		ItemsShown int `json:"items_shown"`
		Total      int
	}
	if out := Run(context.Background(), Env{}, list, nil); len(out) > MaxResult || json.Unmarshal(out, &shrunk) != nil || shrunk.ItemsShown == 0 || shrunk.Total != 400 {
		t.Fatalf("list not shrunk to valid JSON: %d %s", len(out), out[:80])
	}
	big := Tool{Name: "y", Run: func(context.Context, Env, map[string]any) (any, error) { return strings.Repeat("a", MaxResult*2), nil }}
	if out := Run(context.Background(), Env{}, big, nil); len(out) > MaxResult+200 || !strings.Contains(string(out), `"truncated":true`) {
		t.Fatalf("not truncated: %d", len(out))
	}
}

// loopModel always asks for a tool.
type loopModel struct{ turns int }

func (m *loopModel) Enabled() bool        { return true }
func (m *loopModel) Provider() string     { return "fake" }
func (m *loopModel) NextRetry() time.Time { return time.Time{} }
func (m *loopModel) Call(context.Context, string, string, llm.Tool, int) (*llm.Result, error) {
	return nil, nil
}
func (m *loopModel) Chat(_ context.Context, req llm.ChatRequest) (*llm.ChatReply, error) {
	m.turns++
	if len(req.Tools) == 0 {
		req.OnText("done")
		return &llm.ChatReply{Text: "done"}, nil
	}
	return &llm.ChatReply{ToolCalls: []llm.ToolCall{{ID: "1", Name: "nope"}}}, nil
}

func TestAskStopsAfterMaxSteps(t *testing.T) {
	m := &loopModel{}
	ans, err := Ask(context.Background(), m, Env{P: &auth.Principal{TenantID: "t", Role: "member"}}, nil, "q", PageContext{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.turns != MaxSteps+1 || len(ans.Steps) != MaxSteps || ans.Text != "done" || ans.Steps[0].Error != "unknown tool nope" {
		t.Fatalf("turns=%d steps=%d %+v", m.turns, len(ans.Steps), ans)
	}
}

func TestToolsForRole(t *testing.T) {
	has := func(ts []Tool, name string) bool {
		for _, t := range ts {
			if t.Name == name {
				return true
			}
		}
		return false
	}
	member := Env{P: &auth.Principal{Role: "member"}}
	admin := Env{P: &auth.Principal{Role: "admin"}}
	if has(For(member, false), "audit_log") || !has(For(admin, false), "audit_log") || has(For(admin, true), "audit_log") {
		t.Fatal("audit_log gating")
	}
	if !has(For(member, false), "check_packages") || has(For(member, true), "check_packages") {
		t.Fatal("check_packages: assistant only (MCP has its own)")
	}
	if Sources("see [a](/fix-queue) and [b](https://evil.example/x) and [a](/fix-queue)")[0].URL != "/fix-queue" || len(Sources("[b](https://evil.example)")) != 0 {
		t.Fatal("sources")
	}
}
