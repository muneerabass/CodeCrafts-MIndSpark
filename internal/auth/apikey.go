package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"
)

const (
	keyPrefix = "dg_"
	keyLen    = 32
	base62    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// GenerateKey returns a new API key, its display prefix and sha256 hash.
func GenerateKey() (key, prefix string, hash []byte, err error) {
	b := make([]byte, keyLen)
	max := big.NewInt(int64(len(base62)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", "", nil, err
		}
		b[i] = base62[n.Int64()]
	}
	key = keyPrefix + string(b)
	h := sha256.Sum256([]byte(key))
	return key, key[:12], h[:], nil
}

// APIKey is the listable form of a key (never includes the secret).
type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	Key        string     `json:"key,omitempty"` // only on create
}

// CreateKey stores a new key for tenantID and returns it with the secret.
func CreateKey(ctx context.Context, pool *pgxpool.Pool, tenantID, userID, name string, expiresAt *time.Time) (*APIKey, error) {
	key, prefix, hash, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	k := &APIKey{ID: ids.New(), Name: name, Prefix: prefix, ExpiresAt: expiresAt, Key: key}
	err = db.WithTenantTx(ctx, pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO api_keys (id, tenant_id, name, prefix, key_hash, created_by, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`,
			k.ID, tenantID, name, prefix, hash, userID, expiresAt).Scan(&k.CreatedAt)
	})
	if err != nil {
		return nil, err
	}
	return k, nil
}

// ListKeys returns the tenant's non-revoked keys, newest first.
func ListKeys(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]APIKey, error) {
	out := []APIKey{}
	err := db.WithTenantTx(ctx, pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, name, prefix, created_at, last_used_at, expires_at
			FROM api_keys WHERE revoked_at IS NULL ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (APIKey, error) {
			var k APIKey
			err := r.Scan(&k.ID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt)
			return k, err
		})
		return err
	})
	return out, err
}

// ErrNotFound is returned when a key does not exist for the tenant.
var ErrNotFound = errors.New("not found")

// RevokeKey marks a key revoked.
func RevokeKey(ctx context.Context, pool *pgxpool.Pool, tenantID, id string) error {
	return db.WithTenantTx(ctx, pool, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// ErrInvalidKey is returned for unknown, revoked, expired or disabled keys.
var ErrInvalidKey = errors.New("invalid api key")

// VerifyKey resolves an API key to its tenant principal and records usage
// (at most once a minute per key).
func VerifyKey(ctx context.Context, pool *pgxpool.Pool, key string) (*Principal, error) {
	if !strings.HasPrefix(key, keyPrefix) || len(key) != len(keyPrefix)+keyLen {
		return nil, ErrInvalidKey
	}
	sum := sha256.Sum256([]byte(key))
	var (
		id, tid    string
		stored     []byte
		revoked    *time.Time
		expires    *time.Time
		tenantDown bool
	)
	err := pool.QueryRow(ctx, `SELECT id, tenant_id, key_hash, revoked_at, expires_at, tenant_disabled
		FROM depguard_api_key_lookup($1)`, sum[:]).Scan(&id, &tid, &stored, &revoked, &expires, &tenantDown)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidKey
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(stored, sum[:]) != 1 || revoked != nil ||
		(expires != nil && !expires.After(time.Now())) || tenantDown {
		return nil, ErrInvalidKey
	}
	err = db.WithTenantTx(ctx, pool, tid, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_keys SET last_used_at = now()
			WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &Principal{TenantID: tid, APIKeyID: id}, nil
}

// APIKeyMiddleware authenticates `Authorization: Bearer dg_...` and applies a
// per-key rate limit (rps sustained, burst).
func APIKeyMiddleware(pool *pgxpool.Pool, rps float64, burst int, next http.Handler) http.Handler {
	var limiters sync.Map // key id -> *rate.Limiter
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := VerifyKey(r.Context(), pool, bearer(r))
		if errors.Is(err, ErrInvalidKey) {
			JSONError(w, http.StatusUnauthorized, "invalid api key")
			return
		}
		if err != nil {
			JSONError(w, http.StatusInternalServerError, "auth lookup failed")
			return
		}
		l, _ := limiters.LoadOrStore(p.APIKeyID, rate.NewLimiter(rate.Limit(rps), burst))
		if !l.(*rate.Limiter).Allow() {
			w.Header().Set("Retry-After", "1")
			JSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}
