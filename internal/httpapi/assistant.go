package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/depguard/depguard/internal/assist"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/llm"
	"github.com/jackc/pgx/v5"
)

const conversationTTL = "30 days"

// A question and its answer are saved in one transaction (same created_at): the question sorts first.
const (
	msgOrder     = "created_at, role = 'assistant'"
	msgOrderDesc = "created_at DESC, role = 'assistant' DESC"
)

func (s *Server) assistEnv(r *http.Request) assist.Env {
	return assist.Env{P: principal(r), API: s.api, SQL: s.d.AISQL, Check: s.d.CheckPackages}
}

func (s *Server) aiConfigured() bool { return llm.On(s.d.AI) }

func (s *Server) assistantEnabled(r *http.Request) (bool, error) {
	var raw []byte
	err := s.tx(r, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT assistant FROM tenant_settings`).Scan(&raw)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	var c struct{ Enabled *bool }
	_ = json.Unmarshal(raw, &c)
	return c.Enabled == nil || *c.Enabled, err
}

func (s *Server) getAssistantSettings(w http.ResponseWriter, r *http.Request) error {
	enabled, err := s.assistantEnabled(r)
	if err != nil {
		return err
	}
	out := map[string]any{"enabled": enabled, "configured": s.aiConfigured(), "provider": "", "model": ""}
	if s.aiConfigured() {
		out["provider"] = s.d.AI.Provider()
	}
	var questions, in, outTok int64
	var model string
	err = s.tx(r, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT count(*), COALESCE(sum(input_tokens),0), COALESCE(sum(output_tokens),0),
			COALESCE((array_agg(model ORDER BY id DESC))[1], '')
			FROM assistant_messages WHERE role = 'assistant' AND created_at > now() - interval '30 days'`).Scan(&questions, &in, &outTok, &model)
	})
	if err != nil {
		return err
	}
	out["model"] = model
	out["usage_30d"] = map[string]int64{"questions": questions, "input_tokens": in, "output_tokens": outTok}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) putAssistantSettings(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if body.Enabled == nil {
		return badRequest("enabled is required")
	}
	b, _ := json.Marshal(map[string]bool{"enabled": *body.Enabled})
	err := s.tx(r, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `UPDATE tenant_settings SET assistant = $1`, b)
		return err
	})
	if err != nil {
		return err
	}
	return s.getAssistantSettings(w, r)
}

type briefingItem struct {
	Tone string `json:"tone"` // red | amber | green
	Text string `json:"text"`
	URL  string `json:"url"`
}

// briefing is the "needs attention" list shown when the popup opens (no AI).
func (s *Server) assistantBriefing(w http.ResponseWriter, r *http.Request) error {
	enabled, err := s.assistantEnabled(r)
	if err != nil {
		return err
	}
	e := s.assistEnv(r)
	ctx := r.Context()
	total := func(path string, q url.Values) int64 {
		raw, err := assist.Call(ctx, e, http.MethodGet, path, q)
		var v struct{ Total int64 }
		if err == nil {
			_ = json.Unmarshal(raw, &v)
		}
		return v.Total
	}
	plural := func(n int64, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	}
	items := []briefingItem{}
	if n := total("/pull-requests", url.Values{"level": {"critical"}}); n > 0 {
		items = append(items, briefingItem{"red", plural(n, "pull request is", "pull requests are") + " critical and should not be merged as is", "/pull-requests"})
	}
	if raw, err := assist.Call(ctx, e, http.MethodGet, "/vaults", nil); err == nil {
		var v struct{ Items []struct{ Leaks int64 } }
		_ = json.Unmarshal(raw, &v)
		var n int64
		for _, it := range v.Items {
			n += it.Leaks
		}
		if n > 0 {
			items = append(items, briefingItem{"red", plural(n, "vault secret was", "vault secrets were") + " found in a pull request: rotate them", "/secrets"})
		}
	}
	if n := total("/vulnerabilities", url.Values{"overdue": {"1"}}); n > 0 {
		items = append(items, briefingItem{"amber", plural(n, "vulnerability is", "vulnerabilities are") + " past the fix deadline", "/fix-queue"})
	}
	if raw, err := assist.Call(ctx, e, http.MethodGet, "/fix-queue", nil); err == nil {
		var v struct {
			Items []struct {
				Name    string  `json:"name"`
				Version string  `json:"version"`
				FixedIn string  `json:"fixed_in"`
				Share   float64 `json:"share"`
			}
		}
		_ = json.Unmarshal(raw, &v)
		if len(v.Items) > 0 && v.Items[0].FixedIn != "" {
			it := v.Items[0]
			items = append(items, briefingItem{"amber", fmt.Sprintf("Top fix: upgrade %s %s to %s (removes %.0f%% of open risk)", it.Name, it.Version, it.FixedIn, it.Share), "/fix-queue"})
		}
	}
	if len(items) == 0 {
		items = append(items, briefingItem{"green", "Nothing urgent right now: no critical pull requests, leaked secrets or overdue fixes.", "/dashboard"})
	}
	return writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled, "configured": s.aiConfigured(), "items": items})
}

func (s *Server) assistantChat(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		ConversationID string             `json:"conversation_id"`
		Message        string             `json:"message"`
		Context        assist.PageContext `json:"context"`
	}
	if err := decode(w, r, 64<<10, &body); err != nil {
		return err
	}
	body.Message = strings.TrimSpace(body.Message)
	if body.Message == "" || utf8.RuneCountInString(body.Message) > 4000 {
		return badRequest("message must be 1-4000 characters")
	}
	enabled, err := s.assistantEnabled(r)
	if err != nil {
		return err
	}
	if !enabled {
		return errf(http.StatusForbidden, "the assistant is turned off for this workspace (Settings → AI)")
	}
	if !s.aiConfigured() {
		return errf(http.StatusServiceUnavailable, "AI is not configured on this server")
	}
	p := principal(r)
	ctx := r.Context()

	// Conversation and the last turns of history (the user's own only).
	var history []assist.Turn
	convID := body.ConversationID
	err = s.tx(r, func(tx pgx.Tx) error {
		if convID != "" {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM assistant_conversations WHERE id = $1 AND user_id = $2`, convID, p.UserID).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return errNotFound
			}
			rows, err := tx.Query(ctx, `SELECT role, text FROM (SELECT created_at, role, text FROM assistant_messages
				WHERE conversation_id = $1 ORDER BY `+msgOrderDesc+` LIMIT 12) m ORDER BY `+msgOrder, convID)
			if err != nil {
				return err
			}
			for rows.Next() {
				var t assist.Turn
				if err := rows.Scan(&t.Role, &t.Text); err != nil {
					return err
				}
				history = append(history, t)
			}
			return rows.Err()
		}
		convID = ids.New()
		title := body.Message
		if utf8.RuneCountInString(title) > 80 {
			title = string([]rune(title)[:80]) + "…"
		}
		_, err := tx.Exec(ctx, `INSERT INTO assistant_conversations (id, tenant_id, user_id, title) VALUES ($1,$2,$3,$4)`, convID, p.TenantID, p.UserID, title)
		return err
	})
	if err != nil {
		return err
	}

	// Server-sent events from here on.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(4 * time.Minute))
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(event string, data any) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		_ = rc.Flush()
	}
	send("start", map[string]string{"conversation_id": convID})

	actx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	ans, err := assist.Ask(actx, s.d.AI, s.assistEnv(r), history, body.Message, body.Context,
		func(d string) { send("text", map[string]string{"delta": d}) },
		func(st assist.Step) { send("step", st) })
	if err != nil {
		s.log.WarnContext(ctx, "assistant failed", "err", err)
		msg := "The AI service is busy or unavailable right now. Please try again in a few minutes."
		if errors.Is(err, context.DeadlineExceeded) {
			msg = "That took too long. Try a narrower question."
		}
		send("error", map[string]string{"message": msg})
		return nil
	}
	msgID := ids.New()
	steps, _ := json.Marshal(ans.Steps)
	sources, _ := json.Marshal(ans.Sources)
	err = s.tx(r, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO assistant_messages (id, tenant_id, conversation_id, role, text) VALUES ($1,$2,$3,'user',$4)`,
			ids.New(), p.TenantID, convID, body.Message); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO assistant_messages (id, tenant_id, conversation_id, role, text, steps, sources, model, input_tokens, output_tokens)
			VALUES ($1,$2,$3,'assistant',$4,$5,$6,$7,$8,$9)`, msgID, p.TenantID, convID, ans.Text, steps, sources, ans.Model, ans.InputTokens, ans.OutputTokens); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE assistant_conversations SET updated_at = now() WHERE id = $1`, convID)
		return err
	})
	if err != nil {
		s.log.ErrorContext(ctx, "assistant: save conversation", "err", err)
	}
	send("done", map[string]any{"conversation_id": convID, "message_id": msgID, "sources": ans.Sources, "steps": ans.Steps,
		"model": ans.Model, "usage": map[string]int{"input_tokens": ans.InputTokens, "output_tokens": ans.OutputTokens}})
	return nil
}

func (s *Server) listConversations(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('id', id, 'title', title, 'updated_at', updated_at)
			ORDER BY updated_at DESC), '[]') FROM (SELECT * FROM assistant_conversations WHERE user_id = $1
			AND updated_at > now() - interval '`+conversationTTL+`' ORDER BY updated_at DESC LIMIT 50) c`, principal(r).UserID)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) getConversation(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `SELECT jsonb_build_object('id', c.id, 'title', c.title, 'messages',
			COALESCE((SELECT jsonb_agg(jsonb_build_object('id', m.id, 'role', m.role, 'text', m.text, 'steps', m.steps,
				'sources', m.sources, 'created_at', m.created_at) ORDER BY m.created_at, m.role = 'assistant') FROM assistant_messages m WHERE m.conversation_id = c.id), '[]'))
			FROM assistant_conversations c WHERE c.id = $1 AND c.user_id = $2`, r.PathValue("id"), principal(r).UserID)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteConversation(w http.ResponseWriter, r *http.Request) error {
	var n int64
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `DELETE FROM assistant_conversations WHERE id = $1 AND user_id = $2`, r.PathValue("id"), principal(r).UserID)
		n = tag.RowsAffected()
		return err
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotFound
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
