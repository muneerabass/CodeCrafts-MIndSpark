package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBedrockChatToolRoundTrip(t *testing.T) {
	var got map[string]any
	c, _ := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"output":{"message":{"content":[{"text":"Looking."},{"toolUse":{"toolUseId":"t1","name":"fix_queue","input":{"limit":3}}}]}},"usage":{"inputTokens":10,"outputTokens":4}}`))
	}, Target{Region: "eu-west-1", Model: "m"})
	var streamed string
	r, err := c.Chat(context.Background(), ChatRequest{System: "s", Tools: []Tool{tool}, OnText: func(d string) { streamed += d },
		Messages: []Msg{
			{Role: "user", Text: "q"},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "t0", Name: "report", Args: json.RawMessage(`{}`)}}},
			{Role: "user", ToolResults: []ToolResult{{ID: "t0", Name: "report", Content: json.RawMessage(`[1,2]`)}}},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ToolCalls) != 1 || r.ToolCalls[0].ID != "t1" || r.ToolCalls[0].Name != "fix_queue" || string(r.ToolCalls[0].Args) != `{"limit":3}` {
		t.Fatalf("tool calls %+v", r.ToolCalls)
	}
	if r.Text != "Looking." || streamed != "Looking." || r.InputTokens != 10 {
		t.Fatalf("reply %+v streamed %q", r, streamed)
	}
	b, _ := json.Marshal(got)
	for _, want := range []string{`"toolUseId":"t0"`, `"json":{"result":[1,2]}`, `"toolSpec"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("request missing %s: %s", want, b)
		}
	}
}

func fakeGemini(t *testing.T, h http.HandlerFunc) (*Gemini, *[]string) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-goog-api-key") != "gk" {
			t.Errorf("missing api key header")
		}
		paths = append(paths, r.URL.Path+"?"+r.URL.RawQuery)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	g := NewGemini("gk", nil)
	g.SetBaseForTest(srv.URL)
	return g, &paths
}

func TestGeminiStreamAndToolCalls(t *testing.T) {
	var body string
	g, paths := fakeGemini(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"candidates":[{"content":{"parts":[{"text":"thinking","thought":true},{"text":"Hel"}]}}]}`+"\n\n")
		_, _ = io.WriteString(w, `data: {"candidates":[{"content":{"parts":[{"text":"lo"},{"functionCall":{"id":"x9","name":"fix_queue","args":{"limit":2}},"thoughtSignature":"sig"}]}}],"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":3,"thoughtsTokenCount":2}}`+"\n\n")
	})
	var deltas []string
	r, err := g.Chat(context.Background(), ChatRequest{System: "sys", Tools: []Tool{tool}, OnText: func(d string) { deltas = append(deltas, d) },
		Messages: []Msg{{Role: "user", Text: "q"}, {Role: "user", ToolResults: []ToolResult{{ID: "g:a1", Name: "report", Content: json.RawMessage(`"ok"`)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if (*paths)[0] != "/models/gemini-flash-lite-latest:streamGenerateContent?alt=sse" {
		t.Fatalf("path %v", *paths)
	}
	if r.Text != "Hello" || strings.Join(deltas, "|") != "Hel|lo" {
		t.Fatalf("text %q deltas %v (thoughts must be hidden)", r.Text, deltas)
	}
	if len(r.ToolCalls) != 1 || r.ToolCalls[0].ID != "g:x9" || string(r.ToolCalls[0].Args) != `{"limit":2}` {
		t.Fatalf("calls %+v", r.ToolCalls)
	}
	if r.InputTokens != 7 || r.OutputTokens != 5 {
		t.Fatalf("usage %+v", r)
	}
	if !strings.Contains(string(r.Raw), `"thoughtSignature":"sig"`) {
		t.Fatalf("raw must keep the thought signature: %s", r.Raw)
	}
	for _, want := range []string{`"parametersJsonSchema"`, `"systemInstruction"`, `"functionResponse":{"id":"a1","name":"report","response":{"result":"ok"}}`} {
		if !strings.Contains(body, want) {
			t.Errorf("request missing %s: %s", want, body)
		}
	}
	// The raw model turn is replayed verbatim on the next request.
	g2, _ := fakeGemini(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"done"}]}}]}`))
	})
	if _, err := g2.Chat(context.Background(), ChatRequest{Messages: []Msg{{Role: "user", Text: "q"}, {Role: "assistant", Raw: r.Raw}}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"parts":[{"text":"thinking","thought":true}`) || !strings.Contains(body, `"thoughtSignature":"sig"`) {
		t.Fatalf("replay %s", body)
	}
}

func TestGeminiFallbackAndForcedCall(t *testing.T) {
	g, paths := fakeGemini(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "flash-lite") {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":429,"message":"Quota exceeded for requests per day"}}`))
			return
		}
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), `"allowedFunctionNames":["report"]`) {
			t.Errorf("forced tool missing: %s", b)
		}
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"report","args":{"risk":"low"}}}]}}]}`))
	})
	res, err := g.Call(context.Background(), "s", "u", tool, 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Input) != `{"risk":"low"}` || res.Model != "gemini-flash-latest" {
		t.Fatalf("%+v", res)
	}
	// The exhausted model is skipped until tomorrow.
	if _, err := g.Call(context.Background(), "s", "u", tool, 100); err != nil {
		t.Fatal(err)
	}
	if len(*paths) != 3 {
		t.Fatalf("lite should be skipped after its daily quota: %v", *paths)
	}
	// Hard turns start on the stronger model.
	if o := g.order(true); o[0] != "gemini-flash-latest" {
		t.Fatalf("order %v", o)
	}
}

func TestGeminiBillingError(t *testing.T) {
	g, _ := fakeGemini(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":429,"message":"Your prepayment credits are depleted."}}`))
	})
	_, err := g.Chat(context.Background(), ChatRequest{Messages: []Msg{{Role: "user", Text: "q"}}})
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "prepayment") {
		t.Fatalf("err %v", err)
	}
	if g.NextRetry().IsZero() {
		t.Fatal("both models should be backed off")
	}
}
