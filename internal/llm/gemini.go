package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultGeminiModels: the cheap model first, the stronger one for hard turns.
var DefaultGeminiModels = []string{"gemini-flash-lite-latest", "gemini-flash-latest"}

// ParseGeminiModels reads "model,model" (DEPGUARD_GEMINI_MODELS); first = default, second = hard.
func ParseGeminiModels(s string) []string {
	var out []string
	for _, m := range strings.Split(s, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// Gemini calls the Gemini API (Google AI Studio key).
type Gemini struct {
	key    string
	models []string
	base   string
	http   *http.Client
	now    func() time.Time

	mu    sync.Mutex
	until map[string]time.Time
	why   map[string]string
}

func NewGemini(key string, models []string) *Gemini {
	if len(models) == 0 {
		models = DefaultGeminiModels
	}
	return &Gemini{key: key, models: models, base: "https://generativelanguage.googleapis.com/v1beta", http: &http.Client{Timeout: 3 * time.Minute},
		now: time.Now, until: map[string]time.Time{}, why: map[string]string{}}
}

// SetBaseForTest points the client at a test server.
func (g *Gemini) SetBaseForTest(base string) { g.base = base }

func (g *Gemini) Enabled() bool    { return g != nil && g.key != "" }
func (g *Gemini) Provider() string { return "gemini" }

func (g *Gemini) NextRetry() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	var first time.Time
	for _, m := range g.models {
		u, ok := g.until[m]
		if !ok || !g.now().Before(u) {
			return time.Time{}
		}
		if first.IsZero() || u.Before(first) {
			first = u
		}
	}
	return first
}

func (g *Gemini) block(m string, d time.Duration, why string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.until[m], g.why[m] = g.now().Add(d), why
}

func (g *Gemini) blocked(m string) (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if u, ok := g.until[m]; ok && g.now().Before(u) {
		return true, g.why[m]
	}
	return false, ""
}

// order puts the model for this turn first and the others after it as fallbacks.
func (g *Gemini) order(hard bool) []string {
	if !hard || len(g.models) < 2 {
		return g.models
	}
	return append([]string{g.models[1], g.models[0]}, g.models[2:]...)
}

type gPart struct {
	Text         string          `json:"text,omitempty"`
	Thought      bool            `json:"thought,omitempty"`
	FunctionCall *gFunctionCall  `json:"functionCall,omitempty"`
	Signature    string          `json:"thoughtSignature,omitempty"`
	Response     json.RawMessage `json:"functionResponse,omitempty"`
}

type gFunctionCall struct {
	ID   string          `json:"id,omitempty"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

type gResponse struct {
	Candidates []struct {
		Content struct {
			Parts []json.RawMessage `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	Usage struct {
		Prompt   int `json:"promptTokenCount"`
		Output   int `json:"candidatesTokenCount"`
		Thoughts int `json:"thoughtsTokenCount"`
	} `json:"usageMetadata"`
}

func (g *Gemini) body(req ChatRequest, force string) map[string]any {
	var contents []map[string]any
	for _, m := range req.Messages {
		if m.Role == "assistant" {
			if len(m.Raw) > 0 {
				contents = append(contents, map[string]any{"role": "model", "parts": m.Raw})
				continue
			}
			var parts []any
			if m.Text != "" {
				parts = append(parts, map[string]any{"text": m.Text})
			}
			for _, tc := range m.ToolCalls {
				parts = append(parts, map[string]any{"functionCall": map[string]any{"name": tc.Name, "args": json.RawMessage(nonEmptyJSON(tc.Args))}})
			}
			contents = append(contents, map[string]any{"role": "model", "parts": parts})
			continue
		}
		var parts []any
		if m.Text != "" {
			parts = append(parts, map[string]any{"text": m.Text})
		}
		for _, tr := range m.ToolResults {
			fr := map[string]any{"name": tr.Name, "response": json.RawMessage(wrapObject(tr.Content))}
			if strings.HasPrefix(tr.ID, "g:") {
				fr["id"] = strings.TrimPrefix(tr.ID, "g:")
			}
			parts = append(parts, map[string]any{"functionResponse": fr})
		}
		contents = append(contents, map[string]any{"role": "user", "parts": parts})
	}
	b := map[string]any{
		"contents":         contents,
		"generationConfig": map[string]any{"maxOutputTokens": max(req.MaxTokens, 4096), "temperature": 0.2},
	}
	if req.System != "" {
		b["systemInstruction"] = map[string]any{"parts": []map[string]any{{"text": req.System}}}
	}
	if len(req.Tools) > 0 {
		var decls []map[string]any
		for _, t := range req.Tools {
			decls = append(decls, map[string]any{"name": t.Name, "description": t.Description, "parametersJsonSchema": t.Schema})
		}
		b["tools"] = []map[string]any{{"functionDeclarations": decls}}
		if force != "" {
			b["toolConfig"] = map[string]any{"functionCallingConfig": map[string]any{"mode": "ANY", "allowedFunctionNames": []string{force}}}
		}
	}
	return b
}

type gError struct {
	Error *struct {
		Message string `json:"message"`
		Details []struct {
			Type       string `json:"@type"`
			RetryDelay string `json:"retryDelay"`
			Violations []struct {
				QuotaID string `json:"quotaId"`
			} `json:"violations"`
		} `json:"details"`
	} `json:"error"`
}

// classify turns an API error into a back-off and an error. Every 429 text
// mentions "plan and billing", so the quota details decide, not the wording.
func (g *Gemini) classify(model string, status int, raw []byte) error {
	var e gError
	_ = json.Unmarshal(raw, &e)
	msg := string(raw)
	retry, perDay := time.Duration(0), false
	if e.Error != nil {
		msg = e.Error.Message
		for _, d := range e.Error.Details {
			if v, err := time.ParseDuration(d.RetryDelay); err == nil && d.RetryDelay != "" {
				retry = v
			}
			for _, q := range d.Violations {
				perDay = perDay || strings.Contains(q.QuotaID, "PerDay")
			}
		}
	}
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "prepayment") || strings.Contains(low, "credits are depleted"):
		g.block(model, time.Hour, "billing: "+firstN(msg, 120))
	case status == http.StatusTooManyRequests && perDay:
		next := g.now().UTC().Truncate(24 * time.Hour).Add(24*time.Hour + 5*time.Minute)
		g.block(model, next.Sub(g.now()), "daily quota used")
	case status == http.StatusTooManyRequests:
		if retry <= 0 {
			retry = time.Minute
		}
		g.block(model, retry+time.Second, "rate limited")
	case status == http.StatusNotFound || status == http.StatusForbidden:
		g.block(model, 6*time.Hour, "not available to this key")
	case status >= 500:
		g.block(model, time.Minute, fmt.Sprintf("HTTP %d", status))
	}
	return fmt.Errorf("gemini %s: HTTP %d: %s", model, status, firstN(msg, 300))
}

// turn sends one request; with onText it streams (SSE) and reports text deltas.
func (g *Gemini) turn(ctx context.Context, model string, body map[string]any, onText func(string)) (*ChatReply, error) {
	payload, _ := json.Marshal(body)
	method := ":generateContent"
	if onText != nil {
		method = ":streamGenerateContent?alt=sse"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.base+"/models/"+model+method, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", g.key)
	res, err := g.http.Do(req)
	if err != nil {
		g.block(model, time.Minute, "unreachable")
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return nil, g.classify(model, res.StatusCode, raw)
	}
	reply := &ChatReply{Model: model}
	var parts []json.RawMessage
	add := func(r gResponse) {
		if r.Usage.Prompt > 0 {
			reply.InputTokens = r.Usage.Prompt
		}
		if r.Usage.Output+r.Usage.Thoughts > 0 {
			reply.OutputTokens = r.Usage.Output + r.Usage.Thoughts
		}
		if len(r.Candidates) == 0 {
			return
		}
		for _, raw := range r.Candidates[0].Content.Parts {
			var p gPart
			if json.Unmarshal(raw, &p) != nil {
				continue
			}
			parts = append(parts, raw)
			switch {
			case p.FunctionCall != nil:
				id := fmt.Sprintf("call_%d", len(reply.ToolCalls))
				if p.FunctionCall.ID != "" {
					id = "g:" + p.FunctionCall.ID
				}
				reply.ToolCalls = append(reply.ToolCalls, ToolCall{ID: id, Name: p.FunctionCall.Name, Args: p.FunctionCall.Args})
			case p.Text != "" && !p.Thought:
				reply.Text += p.Text
				if onText != nil {
					onText(p.Text)
				}
			}
		}
	}
	if onText == nil {
		var r gResponse
		if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&r); err != nil {
			return nil, err
		}
		add(r)
	} else {
		sc := bufio.NewScanner(res.Body)
		sc.Buffer(make([]byte, 64<<10), 8<<20)
		for sc.Scan() {
			line, ok := strings.CutPrefix(sc.Text(), "data:")
			if !ok {
				continue
			}
			var r gResponse
			if json.Unmarshal([]byte(strings.TrimSpace(line)), &r) == nil {
				add(r)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	reply.Raw, _ = json.Marshal(parts)
	return reply, nil
}

// MaxWait is how long a turn waits for a rate-limited model to free up.
var MaxWait = 65 * time.Second

// Chat runs one turn, falling back to the other model when one is unavailable.
func (g *Gemini) Chat(ctx context.Context, req ChatRequest) (*ChatReply, error) {
	return g.run(ctx, req, "")
}

func (g *Gemini) run(ctx context.Context, req ChatRequest, force string) (*ChatReply, error) {
	if !g.Enabled() {
		return nil, errors.New("AI is not configured")
	}
	body := g.body(req, force)
	// Per-minute limits (free tier: 15 requests/minute) clear quickly: wait rather than fail.
	if next := g.NextRetry(); !next.IsZero() && next.Sub(g.now()) <= MaxWait {
		select {
		case <-time.After(next.Sub(g.now())):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var errs []string
	for _, m := range g.order(req.Hard) {
		if wait, why := g.blocked(m); wait {
			errs = append(errs, m+": "+why)
			continue
		}
		r, err := g.turn(ctx, m, body, req.OnText)
		if err == nil {
			return r, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		errs = append(errs, err.Error())
	}
	return nil, fmt.Errorf("%w (%s)", ErrUnavailable, strings.Join(errs, "; "))
}

// Call forces the model to answer through one tool (PR AI review).
func (g *Gemini) Call(ctx context.Context, system, user string, tool Tool, maxTokens int) (*Result, error) {
	r, err := g.run(ctx, ChatRequest{System: system, Messages: []Msg{{Role: "user", Text: user}}, Tools: []Tool{tool}, MaxTokens: maxTokens}, tool.Name)
	if err != nil {
		return nil, err
	}
	out := &Result{Model: r.Model, InputTokens: r.InputTokens, OutputTokens: r.OutputTokens}
	for _, tc := range r.ToolCalls {
		if tc.Name == tool.Name && len(tc.Args) > 0 {
			out.Input = tc.Args
			return out, nil
		}
	}
	if j := jsonObject(r.Text); j != "" {
		out.Input = json.RawMessage(j)
		return out, nil
	}
	return nil, errors.New("the model returned no structured answer")
}
