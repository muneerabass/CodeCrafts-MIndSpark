// Package llm calls models on Amazon Bedrock (Converse API) with a Bedrock API
// key, trying a list of region/model targets in order: a target that is out of
// quota or unavailable is skipped until it can work again, so one exhausted
// region never stops reviews.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Target is one region/model pair.
type Target struct {
	Region string
	Model  string
}

func (t Target) String() string { return t.Region + "/" + t.Model }

// DefaultTargets: small, cheap, generally available code models first, in the
// regions that served them during setup; then other inexpensive models.
var DefaultTargets = []Target{
	{"eu-west-1", "qwen.qwen3-coder-30b-a3b-v1:0"},
	{"us-east-1", "qwen.qwen3-coder-30b-a3b-v1:0"},
	{"ap-south-1", "qwen.qwen3-coder-30b-a3b-v1:0"},
	{"us-west-2", "qwen.qwen3-coder-30b-a3b-v1:0"},
	{"eu-west-1", "openai.gpt-oss-20b-1:0"},
	{"us-east-1", "openai.gpt-oss-20b-1:0"},
	{"ap-south-1", "openai.gpt-oss-20b-1:0"},
	{"us-east-1", "qwen.qwen3-32b-v1:0"},
}

// ParseTargets reads "region/model,region/model" (DEPGUARD_AI_MODELS).
func ParseTargets(s string) []Target {
	var out []Target
	for _, p := range strings.Split(s, ",") {
		r, m, ok := strings.Cut(strings.TrimSpace(p), "/")
		if ok && r != "" && m != "" {
			out = append(out, Target{r, m})
		}
	}
	return out
}

// ErrUnavailable means every target is rate limited or unavailable right now.
var ErrUnavailable = errors.New("all configured AI models are rate limited or unavailable")

// Client calls the Converse API.
type Client struct {
	token   string
	targets []Target
	http    *http.Client
	// endpoint builds the Converse URL (overridden in tests).
	endpoint func(Target) string
	now      func() time.Time

	mu    sync.Mutex
	until map[Target]time.Time // skip a target until this time
	why   map[Target]string
}

// New returns a client; it is nil-safe to call Enabled on a nil client.
func New(token string, targets []Target) *Client {
	if len(targets) == 0 {
		targets = DefaultTargets
	}
	return &Client{token: token, targets: targets, http: &http.Client{Timeout: 3 * time.Minute},
		endpoint: func(t Target) string {
			return fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com/model/%s/converse", t.Region, t.Model)
		},
		now: time.Now, until: map[Target]time.Time{}, why: map[Target]string{}}
}

// Enabled reports whether a key is configured.
func (c *Client) Enabled() bool { return c != nil && c.token != "" }

// Tool is the single tool the model must call; Schema is a JSON schema object.
type Tool struct {
	Name        string
	Description string
	Schema      map[string]any
}

// Result is the tool input the model produced.
type Result struct {
	Input        json.RawMessage
	Model        string // region/model that answered
	InputTokens  int
	OutputTokens int
}

// Call asks the first available target to answer by calling tool.
func (c *Client) Call(ctx context.Context, system, user string, tool Tool, maxTokens int) (*Result, error) {
	if !c.Enabled() {
		return nil, errors.New("AI review is not configured (no Bedrock API key)")
	}
	body := map[string]any{
		"system":   []map[string]any{{"text": system}},
		"messages": []map[string]any{{"role": "user", "content": []map[string]any{{"text": user}}}},
		"toolConfig": map[string]any{
			"tools":      []map[string]any{{"toolSpec": map[string]any{"name": tool.Name, "description": tool.Description, "inputSchema": map[string]any{"json": tool.Schema}}}},
			"toolChoice": map[string]any{"tool": map[string]any{"name": tool.Name}},
		},
		"inferenceConfig": map[string]any{"maxTokens": maxTokens, "temperature": 0},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var errs []string
	for _, t := range c.targets {
		if wait, why := c.skip(t); wait {
			errs = append(errs, t.String()+": "+why)
			continue
		}
		res, err := c.call(ctx, t, payload)
		if err == nil {
			return res, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		errs = append(errs, t.String()+": "+err.Error())
	}
	return nil, fmt.Errorf("%w (%s)", ErrUnavailable, strings.Join(errs, "; "))
}

func (c *Client) skip(t Target) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if u, ok := c.until[t]; ok && c.now().Before(u) {
		return true, c.why[t]
	}
	return false, ""
}

func (c *Client) block(t Target, d time.Duration, why string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.until[t], c.why[t] = c.now().Add(d), why
}

// NextRetry is when the earliest blocked target may work again (zero if one is free).
func (c *Client) NextRetry() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	var first time.Time
	for _, t := range c.targets {
		u, ok := c.until[t]
		if !ok || !c.now().Before(u) {
			return time.Time{}
		}
		if first.IsZero() || u.Before(first) {
			first = u
		}
	}
	return first
}

type converseResp struct {
	Output struct {
		Message struct {
			Content []struct {
				Text    string `json:"text"`
				ToolUse *struct {
					Input json.RawMessage `json:"input"`
				} `json:"toolUse"`
			} `json:"content"`
		} `json:"message"`
	} `json:"output"`
	Usage struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
	} `json:"usage"`
	Message string `json:"message"`
}

func (c *Client) call(ctx context.Context, t Target, payload []byte) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint(t), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		c.block(t, time.Minute, "unreachable")
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	var r converseResp
	_ = json.Unmarshal(raw, &r)
	switch {
	case res.StatusCode == http.StatusTooManyRequests:
		if strings.Contains(strings.ToLower(r.Message), "per day") {
			// Daily quota: wait for the next UTC day.
			next := c.now().UTC().Truncate(24 * time.Hour).Add(24*time.Hour + 5*time.Minute)
			c.block(t, next.Sub(c.now()), "daily quota used")
		} else {
			c.block(t, 2*time.Minute, "throttled")
		}
		return nil, fmt.Errorf("rate limited: %s", r.Message)
	case res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusBadRequest && strings.Contains(r.Message, "not available"):
		c.block(t, 6*time.Hour, "not available to this account")
		return nil, fmt.Errorf("unavailable: %s", r.Message)
	case res.StatusCode >= 300:
		c.block(t, time.Minute, fmt.Sprintf("HTTP %d", res.StatusCode))
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, firstN(r.Message+string(raw), 200))
	}
	out := &Result{Model: t.Model, InputTokens: r.Usage.InputTokens, OutputTokens: r.Usage.OutputTokens}
	var text strings.Builder
	for _, cnt := range r.Output.Message.Content {
		if cnt.ToolUse != nil && len(cnt.ToolUse.Input) > 0 {
			out.Input = cnt.ToolUse.Input
			return out, nil
		}
		text.WriteString(cnt.Text)
	}
	// Some models answer with JSON text instead of a tool call.
	if j := jsonObject(text.String()); j != "" {
		out.Input = json.RawMessage(j)
		return out, nil
	}
	return nil, errors.New("the model returned no structured answer")
}

var fence = regexp.MustCompile("(?s)```(?:json)?\\s*(\\{.*\\})\\s*```")

// jsonObject extracts the first JSON object from model text.
func jsonObject(s string) string {
	if m := fence.FindStringSubmatch(s); m != nil && json.Valid([]byte(m[1])) {
		return m[1]
	}
	i, j := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if i >= 0 && j > i && json.Valid([]byte(s[i:j+1])) {
		return s[i : j+1]
	}
	return ""
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SetEndpointForTest points every target at base (tests in other packages).
func (c *Client) SetEndpointForTest(base string) {
	c.endpoint = func(t Target) string { return base + "/" + t.Region + "/" + t.Model }
}
