// Package auth verifies callers of the API: service JWTs minted by the web
// server (/api/v1/*) and tenant API keys (/v1/*, /mcp).
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Roles carried in the service JWT.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Principal is the authenticated caller.
type Principal struct {
	TenantID string
	UserID   string
	Role     string
	SA       bool // platform super-admin
	Email    string
	Name     string
	APIKeyID string // set when authenticated by API key
}

// CanWrite reports whether the principal may modify tenant configuration.
func (p *Principal) CanWrite() bool { return p.Role == RoleOwner || p.Role == RoleAdmin }

type ctxKey struct{}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the request principal, or nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// MaxTokenTTL bounds exp-iat (and exp-now) of service JWTs.
const MaxTokenTTL = 60 * time.Second

const leeway = 5 * time.Second

type claims struct {
	TID   string `json:"tid"`
	UID   string `json:"uid"`
	Role  string `json:"role"`
	SA    bool   `json:"sa"`
	Email string `json:"email"`
	Name  string `json:"name"`
	jwt.RegisteredClaims
}

// ParseServiceJWT validates an HS256 service token and returns its principal.
func ParseServiceJWT(secret []byte, token string, now time.Time) (*Principal, error) {
	if len(secret) == 0 {
		return nil, errors.New("service jwt secret not configured")
	}
	var c claims
	_, err := jwt.ParseWithClaims(token, &c, func(*jwt.Token) (any, error) { return secret, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		return nil, err
	}
	exp := c.ExpiresAt.Time
	if exp.Sub(now) > MaxTokenTTL+leeway {
		return nil, errors.New("token lifetime exceeds 60s")
	}
	if c.IssuedAt != nil && exp.Sub(c.IssuedAt.Time) > MaxTokenTTL {
		return nil, errors.New("token lifetime exceeds 60s")
	}
	switch c.Role {
	case RoleOwner, RoleAdmin, RoleMember:
	case "":
		if !c.SA {
			return nil, errors.New("missing role")
		}
	default:
		return nil, errors.New("unknown role")
	}
	return &Principal{TenantID: c.TID, UserID: c.UID, Role: c.Role, SA: c.SA, Email: c.Email, Name: c.Name}, nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// JSONError writes {"error": msg} with status code.
func JSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// JWTMiddleware authenticates service JWTs. Non-admin requests need a tenant.
func JWTMiddleware(secret []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			JSONError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		p, err := ParseServiceJWT(secret, tok, time.Now())
		if err != nil {
			JSONError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// RequireTenant rejects principals without a tenant (e.g. a pure super-admin token).
func RequireTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := FromContext(r.Context())
		if p == nil || p.TenantID == "" || p.Role == "" {
			JSONError(w, http.StatusForbidden, "tenant required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireWrite allows only owner/admin.
func RequireWrite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := FromContext(r.Context()); p == nil || !p.CanWrite() {
			JSONError(w, http.StatusForbidden, "admin or owner role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSA allows only platform super-admins.
func RequireSA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := FromContext(r.Context()); p == nil || !p.SA {
			JSONError(w, http.StatusForbidden, "super-admin required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
