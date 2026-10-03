package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/httpapi/pgtest"
	"github.com/golang-jwt/jwt/v5"
)

var secret = []byte("test-secret")

func sign(t *testing.T, key []byte, method jwt.SigningMethod, c jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, c).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseServiceJWT(t *testing.T) {
	now := time.Now()
	ok := jwt.MapClaims{"tid": "t1", "uid": "u1", "role": "admin", "iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix()}
	p, err := ParseServiceJWT(secret, sign(t, secret, jwt.SigningMethodHS256, ok), now)
	if err != nil || p.TenantID != "t1" || p.Role != RoleAdmin || !p.CanWrite() {
		t.Fatalf("valid token: %v %+v", err, p)
	}
	bad := map[string]string{
		"expired":   sign(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{"tid": "t1", "role": "admin", "exp": now.Add(-time.Minute).Unix()}),
		"no exp":    sign(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{"tid": "t1", "role": "admin"}),
		"long ttl":  sign(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{"tid": "t1", "role": "admin", "exp": now.Add(time.Hour).Unix()}),
		"wrong key": sign(t, []byte("other"), jwt.SigningMethodHS256, ok),
		"wrong alg": sign(t, secret, jwt.SigningMethodHS512, ok),
		"bad role":  sign(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{"tid": "t1", "role": "root", "exp": now.Add(30 * time.Second).Unix()}),
		"no role":   sign(t, secret, jwt.SigningMethodHS256, jwt.MapClaims{"tid": "t1", "exp": now.Add(30 * time.Second).Unix()}),
		"none alg":  "eyJhbGciOiJub25lIn0.eyJ0aWQiOiJ0MSJ9.",
		"garbage":   "x.y.z",
	}
	for name, tok := range bad {
		if _, err := ParseServiceJWT(secret, tok, now); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Small clock skew is tolerated.
	skew := jwt.MapClaims{"tid": "t1", "role": "member", "exp": now.Add(-2 * time.Second).Unix()}
	if _, err := ParseServiceJWT(secret, sign(t, secret, jwt.SigningMethodHS256, skew), now); err != nil {
		t.Errorf("leeway: %v", err)
	}
}

func TestRBACMiddleware(t *testing.T) {
	now := time.Now()
	tok := func(c jwt.MapClaims) string {
		c["exp"] = now.Add(30 * time.Second).Unix()
		return sign(t, secret, jwt.SigningMethodHS256, c)
	}
	okH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	write := JWTMiddleware(secret, RequireTenant(RequireWrite(okH)))
	admin := JWTMiddleware(secret, RequireSA(okH))
	cases := []struct {
		name string
		h    http.Handler
		tok  string
		want int
	}{
		{"no token", write, "", 401},
		{"member write", write, tok(jwt.MapClaims{"tid": "t", "role": "member"}), 403},
		{"admin write", write, tok(jwt.MapClaims{"tid": "t", "role": "admin"}), 204},
		{"owner write", write, tok(jwt.MapClaims{"tid": "t", "role": "owner"}), 204},
		{"sa without tenant on tenant route", write, tok(jwt.MapClaims{"sa": true}), 403},
		{"owner on admin", admin, tok(jwt.MapClaims{"tid": "t", "role": "owner"}), 403},
		{"sa on admin", admin, tok(jwt.MapClaims{"sa": true}), 204},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if c.tok != "" {
			r.Header.Set("Authorization", "Bearer "+c.tok)
		}
		w := httptest.NewRecorder()
		c.h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: got %d want %d", c.name, w.Code, c.want)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	k, prefix, hash, err := GenerateKey()
	if err != nil || len(k) != 35 || prefix != k[:12] || len(hash) != 32 || k[:3] != "dg_" {
		t.Fatalf("bad key %q %q %v", k, prefix, err)
	}
	k2, _, _, _ := GenerateKey()
	if k == k2 {
		t.Fatal("keys not random")
	}
}

var tdb *pgtest.DB

func TestMain(m *testing.M) {
	if os.Getenv("SKIP_DB_TESTS") == "" {
		var err error
		if tdb, err = pgtest.Start(context.Background()); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	if tdb != nil {
		tdb.Close()
	}
	os.Exit(code)
}

func TestAPIKeyLifecycle(t *testing.T) {
	if tdb == nil {
		t.Skip("no db")
	}
	ctx := context.Background()
	if _, err := tdb.Owner.Exec(ctx, `INSERT INTO tenant_settings (tenant_id, domain) VALUES ('ta','a.test'),('tb','b.test')`); err != nil {
		t.Fatal(err)
	}
	k, err := CreateKey(ctx, tdb.App, "ta", "u1", "ci", nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyKey(ctx, tdb.App, k.Key)
	if err != nil || p.TenantID != "ta" || p.APIKeyID != k.ID {
		t.Fatalf("verify: %v %+v", err, p)
	}
	keys, _ := ListKeys(ctx, tdb.App, "ta")
	if len(keys) != 1 || keys[0].LastUsedAt == nil || keys[0].Key != "" {
		t.Fatalf("list: %+v", keys)
	}
	if other, _ := ListKeys(ctx, tdb.App, "tb"); len(other) != 0 {
		t.Fatal("tenant b sees tenant a keys")
	}
	if err := RevokeKey(ctx, tdb.App, "tb", k.ID); err != ErrNotFound {
		t.Fatalf("cross-tenant revoke: %v", err)
	}
	if _, err := VerifyKey(ctx, tdb.App, k.Key[:34]+"x"); err != ErrInvalidKey {
		t.Fatalf("wrong key: %v", err)
	}
	if err := RevokeKey(ctx, tdb.App, "ta", k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyKey(ctx, tdb.App, k.Key); err != ErrInvalidKey {
		t.Fatalf("revoked: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	exp, _ := CreateKey(ctx, tdb.App, "ta", "u1", "old", &past)
	if _, err := VerifyKey(ctx, tdb.App, exp.Key); err != ErrInvalidKey {
		t.Fatalf("expired: %v", err)
	}
	// Disabled tenant keys stop working.
	kb, _ := CreateKey(ctx, tdb.App, "tb", "u1", "b", nil)
	tdb.Owner.Exec(ctx, `UPDATE tenant_settings SET disabled_at = now() WHERE tenant_id = 'tb'`)
	if _, err := VerifyKey(ctx, tdb.App, kb.Key); err != ErrInvalidKey {
		t.Fatalf("disabled tenant: %v", err)
	}
	// Middleware.
	h := APIKeyMiddleware(tdb.App, 1, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(FromContext(r.Context()).TenantID))
	}))
	good, _ := CreateKey(ctx, tdb.App, "ta", "u1", "mw", nil)
	codes := []int{}
	for range 2 {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+good.Key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		codes = append(codes, w.Code)
	}
	if codes[0] != 200 || codes[1] != 429 {
		t.Fatalf("rate limit codes %v", codes)
	}
}
