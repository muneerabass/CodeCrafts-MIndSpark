package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Model is an AI provider: Bedrock today, Gemini when GEMINI_API_KEY is set.
type Model interface {
	Enabled() bool
	Provider() string // "gemini" | "bedrock"
	// Call forces one tool and returns its input (PR AI review).
	Call(ctx context.Context, system, user string, tool Tool, maxTokens int) (*Result, error)
	// Chat is a multi-turn conversation with optional tools (the assistant).
	Chat(ctx context.Context, req ChatRequest) (*ChatReply, error)
	// NextRetry is when a rate-limited provider may work again (zero = now).
	NextRetry() time.Time
}

// FromEnv picks the provider: Gemini when GEMINI_API_KEY is set, else Bedrock
// (AWS_BEARER_TOKEN_BEDROCK, DEPGUARD_AI_MODELS). Neither key → disabled.
func FromEnv() Model {
	if k := os.Getenv("GEMINI_API_KEY"); k != "" {
		return NewGemini(k, ParseGeminiModels(os.Getenv("DEPGUARD_GEMINI_MODELS")))
	}
	return New(os.Getenv("AWS_BEARER_TOKEN_BEDROCK"), ParseTargets(os.Getenv("DEPGUARD_AI_MODELS")))
}

// Msg is one conversation turn. Role is "user" or "assistant".
type Msg struct {
	Role        string
	Text        string
	ToolCalls   []ToolCall   // assistant turn: tools the model asked for
	ToolResults []ToolResult // user turn: answers to those calls
	// Raw is the provider's own encoding of an assistant turn, sent back
	// verbatim (Gemini requires its thought signatures to be returned).
	Raw json.RawMessage
}

// ToolCall is a tool the model wants to run.
type ToolCall struct {
	ID   string
	Name string
	Args json.RawMessage
}

// ToolResult answers a ToolCall; Content is a JSON value.
type ToolResult struct {
	ID      string
	Name    string
	Content json.RawMessage
}

// ChatRequest is one model turn. Hard asks for the stronger model.
type ChatRequest struct {
	System    string
	Messages  []Msg
	Tools     []Tool
	MaxTokens int
	Hard      bool
	OnText    func(delta string) // streamed text, when the provider streams
}

// ChatReply is the model's turn: text and/or tool calls.
type ChatReply struct {
	Text         string
	ToolCalls    []ToolCall
	Raw          json.RawMessage // see Msg.Raw
	Model        string
	InputTokens  int
	OutputTokens int
}

func (c *Client) Provider() string { return "bedrock" }

// Chat runs one Converse turn with tools (auto choice) and failover across targets.
func (c *Client) Chat(ctx context.Context, req ChatRequest) (*ChatReply, error) {
	if !c.Enabled() {
		return nil, errors.New("AI is not configured")
	}
	var msgs []map[string]any
	for _, m := range req.Messages {
		var content []map[string]any
		if m.Text != "" {
			content = append(content, map[string]any{"text": m.Text})
		}
		for _, tc := range m.ToolCalls {
			content = append(content, map[string]any{"toolUse": map[string]any{"toolUseId": tc.ID, "name": tc.Name, "input": json.RawMessage(nonEmptyJSON(tc.Args))}})
		}
		for _, tr := range m.ToolResults {
			content = append(content, map[string]any{"toolResult": map[string]any{"toolUseId": tr.ID,
				"content": []map[string]any{{"json": json.RawMessage(wrapObject(tr.Content))}}}})
		}
		if len(content) == 0 {
			content = append(content, map[string]any{"text": " "})
		}
		msgs = append(msgs, map[string]any{"role": m.Role, "content": content})
	}
	body := map[string]any{
		"system":          []map[string]any{{"text": req.System}},
		"messages":        msgs,
		"inferenceConfig": map[string]any{"maxTokens": max(req.MaxTokens, 512), "temperature": 0.2},
	}
	if len(req.Tools) > 0 {
		var specs []map[string]any
		for _, t := range req.Tools {
			specs = append(specs, map[string]any{"toolSpec": map[string]any{"name": t.Name, "description": t.Description, "inputSchema": map[string]any{"json": t.Schema}}})
		}
		body["toolConfig"] = map[string]any{"tools": specs}
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
		r, err := c.converse(ctx, t, payload)
		if err == nil {
			reply := &ChatReply{Model: t.Model, InputTokens: r.Usage.InputTokens, OutputTokens: r.Usage.OutputTokens}
			var text strings.Builder
			for i, cnt := range r.Output.Message.Content {
				if cnt.ToolUse != nil {
					id := cnt.ToolUse.ToolUseID
					if id == "" {
						id = fmt.Sprintf("call_%d", i)
					}
					reply.ToolCalls = append(reply.ToolCalls, ToolCall{ID: id, Name: cnt.ToolUse.Name, Args: cnt.ToolUse.Input})
				}
				text.WriteString(cnt.Text)
			}
			reply.Text = text.String()
			if req.OnText != nil && reply.Text != "" {
				req.OnText(reply.Text)
			}
			return reply, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		errs = append(errs, t.String()+": "+err.Error())
	}
	return nil, fmt.Errorf("%w (%s)", ErrUnavailable, strings.Join(errs, "; "))
}

func nonEmptyJSON(b json.RawMessage) []byte {
	if len(b) == 0 {
		return []byte("{}")
	}
	return b
}

// wrapObject makes any JSON value an object (Bedrock toolResult json must be one).
func wrapObject(b json.RawMessage) []byte {
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "{") {
		return b
	}
	if s == "" {
		s = "null"
	}
	return []byte(`{"result":` + s + `}`)
}

// On reports whether m is set and configured (nil-safe for interface values).
func On(m Model) bool { return m != nil && m.Enabled() }
