package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/llm"
	"github.com/depguard/depguard/internal/query"
)

// fakeModel asks for each tool in calls (one per turn), then answers.
type fakeModel struct {
	mu      sync.Mutex
	calls   []string
	seen    []llm.ChatRequest
	results []string // tool results the model received
}

func (f *fakeModel) Enabled() bool        { return true }
func (f *fakeModel) Provider() string     { return "fake" }
func (f *fakeModel) NextRetry() time.Time { return time.Time{} }
func (f *fakeModel) Call(context.Context, string, string, llm.Tool, int) (*llm.Result, error) {
	return nil, io.EOF
}
func (f *fakeModel) Chat(_ context.Context, req llm.ChatRequest) (*llm.ChatReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, req)
	last := req.Messages[len(req.Messages)-1]
	for _, r := range last.ToolResults {
		f.results = append(f.results, r.Name+":"+string(r.Content))
	}
	n := 0
	for _, m := range req.Messages {
		n += len(m.ToolCalls)
	}
	if n < len(f.calls) && len(req.Tools) > 0 {
		return &llm.ChatReply{Model: "fake-1", ToolCalls: []llm.ToolCall{{ID: "t" + f.calls[n], Name: f.calls[n], Args: json.RawMessage(`{}`)}}}, nil
	}
	text := "Fix [lodash](/components/c1) first."
	req.OnText("Fix [lodash](/components/c1) ")
	req.OnText("first.")
	return &llm.ChatReply{Model: "fake-1", Text: text, InputTokens: 10, OutputTokens: 5}, nil
}

type sse struct{ events map[string][]string }

func chat(t *testing.T, base, tok string, body map[string]any) (int, sse) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", base+"/api/v1/assistant/chat", strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := sse{events: map[string][]string{}}
	for _, block := range strings.Split(string(raw), "\n\n") {
		ev, data, _ := strings.Cut(block, "\ndata: ")
		if ev = strings.TrimPrefix(ev, "event: "); ev != "" {
			out.events[ev] = append(out.events[ev], data)
		}
	}
	return res.StatusCode, out
}

func TestAssistant(t *testing.T) {
	fm := &fakeModel{calls: []string{"list_projects", "audit_log", "secrets_overview"}}
	asrv := httptest.NewServer(New(Deps{Pool: tdb.App, Query: &query.Executor{Pool: tdb.Query}, AISQL: &query.Executor{Pool: tdb.Query, Role: "depguard_ai"},
		JWTSecret: secret, AI: fm}))
	defer asrv.Close()
	member, owner, other := token("ta", "member", false), token("ta", "owner", false), token("tb", "member", false)

	code, ev := chat(t, asrv.URL, member, map[string]any{"message": "what should I fix first?", "context": map[string]any{"path": "/projects/pa", "project_id": "pa"}})
	if code != 200 || len(ev.events["done"]) != 1 || len(ev.events["error"]) != 0 {
		t.Fatalf("chat %d %v", code, ev.events)
	}
	if got := strings.Join(ev.events["text"], ""); !strings.Contains(got, `lodash](/components/c1)`) {
		t.Fatalf("streamed text %s", got)
	}
	if steps := strings.Join(ev.events["step"], ""); !strings.Contains(steps, "Listing projects") || !strings.Contains(steps, "secrets_overview") {
		t.Fatalf("steps %v", ev.events["step"])
	}
	var done struct {
		ConversationID string `json:"conversation_id"`
		Sources        []struct{ URL string }
	}
	_ = json.Unmarshal([]byte(ev.events["done"][0]), &done)
	if done.ConversationID == "" || len(done.Sources) != 1 || done.Sources[0].URL != "/components/c1" {
		t.Fatalf("done %s", ev.events["done"][0])
	}
	// Page context reaches the model; tools ran as the member of tenant ta.
	if q := fm.seen[0].Messages[len(fm.seen[0].Messages)-1].Text; !strings.Contains(q, "project_id pa") {
		t.Fatalf("question without context: %q", q)
	}
	all := strings.Join(fm.results, "\n")
	if !strings.Contains(all, "acme/web") || strings.Contains(all, `"beta"`) {
		t.Fatalf("list_projects result %s", all)
	}
	if !strings.Contains(all, `audit_log:{"error":"unknown tool audit_log"}`) {
		t.Fatalf("members must not reach the audit log: %s", all)
	}
	for _, tl := range fm.seen[0].Tools {
		if tl.Name == "audit_log" {
			t.Fatal("audit_log offered to a member")
		}
	}

	// History is private to its user.
	cid := done.ConversationID
	conv := expectAt(t, asrv.URL, "GET", "/api/v1/assistant/conversations/"+cid, member, 200)
	if !strings.Contains(conv, "what should I fix first?") || !strings.Contains(conv, "Listing projects") {
		t.Fatalf("conversation %s", conv)
	}
	expectAt(t, asrv.URL, "GET", "/api/v1/assistant/conversations/"+cid, owner, 404)
	expectAt(t, asrv.URL, "GET", "/api/v1/assistant/conversations/"+cid, other, 404)
	if list := expectAt(t, asrv.URL, "GET", "/api/v1/assistant/conversations", owner, 200); strings.Contains(list, cid) {
		t.Fatal("owner sees member's conversation")
	}
	// A follow-up sends the earlier turns as history.
	fm.calls, fm.seen = nil, nil
	if code, ev = chat(t, asrv.URL, member, map[string]any{"conversation_id": cid, "message": "and then?"}); code != 200 || len(ev.events["done"]) != 1 {
		t.Fatalf("follow-up %d %v", code, ev.events)
	}
	if h := fm.seen[0].Messages; len(h) != 3 || h[0].Text != "what should I fix first?" {
		t.Fatalf("history %+v", h)
	}
	if code, _ = chat(t, asrv.URL, other, map[string]any{"conversation_id": cid, "message": "hi"}); code != 404 {
		t.Fatalf("other tenant continued a conversation: %d", code)
	}

	// Owners/admins get the audit log tool.
	fm.calls, fm.seen, fm.results = []string{"audit_log"}, nil, nil
	chat(t, asrv.URL, owner, map[string]any{"message": "who changed the policy?"})
	if r := strings.Join(fm.results, ""); !strings.HasPrefix(r, `audit_log:{"items"`) {
		t.Fatalf("owner audit_log %s", r)
	}

	// Briefing needs no AI.
	if b := expectAt(t, asrv.URL, "GET", "/api/v1/assistant/briefing", member, 200); !strings.Contains(b, `"items":[{`) || !strings.Contains(b, `"enabled":true`) {
		t.Fatalf("briefing %s", b)
	}
	// Settings: usage is counted; only admins switch it off; off means no chat.
	if st := expectAt(t, asrv.URL, "GET", "/api/v1/settings/assistant", member, 200); !strings.Contains(st, `"model":"fake-1"`) || !strings.Contains(st, `"provider":"fake"`) {
		t.Fatalf("settings %s", st)
	}
	expect(t, doAt(t, asrv.URL, "PUT", "/api/v1/settings/assistant", member, map[string]any{"enabled": false}), 403)
	expect(t, doAt(t, asrv.URL, "PUT", "/api/v1/settings/assistant", owner, map[string]any{"enabled": false}), 200)
	if code, _ = chat(t, asrv.URL, member, map[string]any{"message": "hi"}); code != 403 {
		t.Fatalf("disabled assistant answered: %d", code)
	}
	expect(t, doAt(t, asrv.URL, "PUT", "/api/v1/settings/assistant", owner, map[string]any{"enabled": true}), 200)

	expectAt(t, asrv.URL, "DELETE", "/api/v1/assistant/conversations/"+cid, owner, 404)
	expectAt(t, asrv.URL, "DELETE", "/api/v1/assistant/conversations/"+cid, member, 204)
	expectAt(t, asrv.URL, "GET", "/api/v1/assistant/conversations/"+cid, member, 404)
}

func doAt(t *testing.T, base, method, path, tok string, body any) resp {
	t.Helper()
	old := srv.URL
	srv.URL = base
	defer func() { srv.URL = old }()
	return do(t, method, path, tok, body)
}

func expectAt(t *testing.T, base, method, path, tok string, code int) string {
	t.Helper()
	return expect(t, doAt(t, base, method, path, tok, nil), code).raw
}
