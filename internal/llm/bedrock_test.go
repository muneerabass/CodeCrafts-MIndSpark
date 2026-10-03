package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func fakeClient(t *testing.T, h http.HandlerFunc, targets ...Target) (*Client, *[]string) {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	var calls []string
	c := New("test-key", targets)
	c.endpoint = func(tg Target) string {
		calls = append(calls, tg.String())
		return srv.URL + "/" + tg.Region + "/" + tg.Model
	}
	return c, &calls
}

var tool = Tool{Name: "report", Description: "r", Schema: map[string]any{"type": "object"}}

func TestFallbackAndQuota(t *testing.T) {
	c, calls := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(401)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/eu-west-1/"):
			w.WriteHeader(429)
			w.Write([]byte(`{"message":"Too many tokens per day, please wait before trying again."}`))
		case strings.HasPrefix(r.URL.Path, "/us-east-1/"):
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"model is not available for this account"}`))
		default:
			w.Write([]byte(`{"output":{"message":{"content":[{"toolUse":{"input":{"ok":true}}}]}},"usage":{"inputTokens":10,"outputTokens":3}}`))
		}
	}, Target{"eu-west-1", "m"}, Target{"us-east-1", "m"}, Target{"ap-south-1", "m"})
	res, err := c.Call(context.Background(), "sys", "user", tool, 100)
	if err != nil || string(res.Input) != `{"ok":true}` || res.Model != "m" || res.InputTokens != 10 {
		t.Fatalf("res %+v err %v", res, err)
	}
	if strings.Join(*calls, ",") != "eu-west-1/m,us-east-1/m,ap-south-1/m" {
		t.Fatalf("calls %v", *calls)
	}
	// The exhausted and unavailable targets are skipped on the next call.
	*calls = nil
	if _, err := c.Call(context.Background(), "s", "u", tool, 100); err != nil || strings.Join(*calls, ",") != "ap-south-1/m" {
		t.Fatalf("second call %v err %v", *calls, err)
	}
}

func TestAllUnavailable(t *testing.T) {
	c, _ := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte(`{"message":"Too many tokens per day"}`))
	}, Target{"a", "m"}, Target{"b", "m"})
	now := time.Date(2026, 10, 4, 15, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	_, err := c.Call(context.Background(), "s", "u", tool, 100)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err %v", err)
	}
	if next := c.NextRetry(); !next.Equal(time.Date(2026, 10, 5, 0, 5, 0, 0, time.UTC)) {
		t.Fatalf("next retry %v", next)
	}
	if New("", nil).Enabled() || (*Client)(nil).Enabled() {
		t.Fatal("no key must mean disabled")
	}
}

func TestTextJSONFallback(t *testing.T) {
	c, _ := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{"output": map[string]any{"message": map[string]any{"content": []map[string]any{{"text": "Here:\n```json\n{\"findings\":[]}\n```"}}}}})
		w.Write(b)
	}, Target{"x", "m"})
	res, err := c.Call(context.Background(), "s", "u", tool, 100)
	if err != nil || string(res.Input) != `{"findings":[]}` {
		t.Fatalf("res %+v err %v", res, err)
	}
}

func TestParseTargets(t *testing.T) {
	got := ParseTargets(" eu-west-1/qwen.qwen3-coder-30b-a3b-v1:0 , bad, us-east-1/openai.gpt-oss-20b-1:0")
	if len(got) != 2 || got[0].Model != "qwen.qwen3-coder-30b-a3b-v1:0" || got[1].Region != "us-east-1" {
		t.Fatalf("%v", got)
	}
}

// TestLiveBedrock calls the real service: AWS_BEARER_TOKEN_BEDROCK=... LLM_LIVE=1 go test -run TestLiveBedrock
func TestLiveBedrock(t *testing.T) {
	if os.Getenv("LLM_LIVE") == "" || os.Getenv("AWS_BEARER_TOKEN_BEDROCK") == "" {
		t.Skip("LLM_LIVE and AWS_BEARER_TOKEN_BEDROCK not set")
	}
	c := New(os.Getenv("AWS_BEARER_TOKEN_BEDROCK"), ParseTargets(os.Getenv("DEPGUARD_AI_MODELS")))
	res, err := c.Call(context.Background(), "Answer by calling the tool.", "Say ok.", Tool{Name: "answer", Description: "answer",
		Schema: map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}, "required": []string{"text"}}}, 50)
	if err != nil {
		t.Skipf("live call unavailable: %v", err)
	}
	t.Logf("model %s answered %s (%d in / %d out tokens)", res.Model, res.Input, res.InputTokens, res.OutputTokens)
}
