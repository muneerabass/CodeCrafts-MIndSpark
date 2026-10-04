package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/ids"
	"github.com/jackc/pgx/v5"
)

type auditKey struct{}

// auditDetail adds a safe detail (never a secret) to the audit entry of this request.
func auditDetail(r *http.Request, k string, v any) {
	if m, ok := r.Context().Value(auditKey{}).(map[string]any); ok {
		m[k] = v
	}
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

var pathParam = regexp.MustCompile(`\{(\w+)(?:\.\.\.)?\}`)

// audited records every successful non-GET request: who, what (route), on
// what (path parameters) and handler-provided details. Bodies are not stored.
func (s *Server) audited(next http.Handler, kind string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Pattern == "POST /api/v1/audit" || r.Pattern == "POST /api/v1/policy/test" {
			next.ServeHTTP(w, r)
			return
		}
		details := map[string]any{}
		r = r.WithContext(context.WithValue(r.Context(), auditKey{}, details))
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.code >= 400 {
			return
		}
		method, route, _ := strings.Cut(r.Pattern, " ")
		route = strings.TrimPrefix(route, "/api/v1")
		e := auditEntry{Kind: kind, Action: method + " " + route, Details: details}
		segs := strings.Split(route, "/")
		for i, seg := range segs {
			if m := pathParam.FindStringSubmatch(seg); m != nil {
				if e.TargetID == "" {
					e.TargetID = r.PathValue(m[1])
					if i > 0 {
						e.TargetType = strings.TrimSuffix(segs[i-1], "s")
					}
				} else {
					details[m[1]] = r.PathValue(m[1])
				}
			}
		}
		s.writeAudit(r, e)
	})
}

type auditEntry struct {
	Kind, Action, TargetType, TargetID string
	Details                            map[string]any
}

func (s *Server) writeAudit(r *http.Request, e auditEntry) {
	p := auth.FromContext(r.Context())
	if p == nil {
		return
	}
	tenant := p.TenantID
	if tenant == "" && strings.HasPrefix(r.Pattern, "PATCH /api/v1/admin/tenants/") {
		tenant = r.PathValue("id") // super-admin action on a tenant
	}
	if tenant == "" {
		return
	}
	kind := e.Kind
	if p.APIKeyID != "" {
		kind = "api_key"
		e.Details["api_key_id"] = p.APIKeyID
	}
	ip := ""
	if kind == "api_key" { // web requests come from the web server; API keys from the client
		ip = strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
	}
	d, _ := json.Marshal(e.Details)
	err := db.WithTenantTx(context.WithoutCancel(r.Context()), s.d.Pool, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO audit_log (id, tenant_id, actor_id, actor_email, actor_role, actor_kind, action, target_type, target_id, details, ip)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, ids.New(), tenant, p.UserID, firstNonEmpty(p.Email, p.Name), p.Role, kind,
			trunc(e.Action, 200), trunc(e.TargetType, 100), trunc(e.TargetID, 200), d, ip)
		return err
	})
	if err != nil {
		s.log.Warn("audit log write failed", "action", e.Action, "err", err)
	}
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `SELECT id, actor_id, actor_email, actor_role, actor_kind, action, target_type, target_id, details, ip, created_at FROM audit_log`,
		filterSpec{ilike: map[string]string{"actor": "t.actor_email", "action": "t.action"}, eq: map[string]string{"kind": "t.actor_kind"}, dateCol: "t.created_at"},
		"t.created_at DESC, t.id DESC", nil)(w, r)
}

var webAction = regexp.MustCompile(`^web:[a-z_.]{3,60}$`)

// recordAudit stores an event for changes made by the web app outside this
// API (members, invitations, organization name).
func (s *Server) recordAudit(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Action     string         `json:"action"`
		TargetType string         `json:"target_type"`
		TargetID   string         `json:"target_id"`
		Details    map[string]any `json:"details"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if !webAction.MatchString(body.Action) {
		return badRequest("action must look like web:member.invite")
	}
	if body.Details == nil {
		body.Details = map[string]any{}
	}
	s.writeAudit(r, auditEntry{Kind: "user", Action: body.Action, TargetType: body.TargetType, TargetID: body.TargetID, Details: body.Details})
	return writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}
