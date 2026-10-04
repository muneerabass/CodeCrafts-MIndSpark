package httpapi

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/vaultcrypto"
	"github.com/jackc/pgx/v5"
)

// The project vault is end-to-end encrypted (internal/vaultcrypto,
// web/lib/vault-crypto.ts): these handlers only store public keys, wrapped
// keys and ciphertext, and check who may fetch what.

const (
	vaultItemLimit = 2 << 20 // 2 MiB request (≈1.4 MiB file after base64)
	maxVaultItems  = 20      // keeps a key rotation (every item re-sent at once) small
)

var (
	vaultName = regexp.MustCompile(`^[A-Za-z0-9._@+-][A-Za-z0-9._@+/ -]{0,119}$`)
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func validB64(s string, min, max int) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) >= min && len(b) <= max
}

func validWrappedKey(w vaultcrypto.WrappedKey) bool {
	return validB64(w.EphemeralPublic, 65, 65) && validB64(w.IV, 12, 12) && validB64(w.Ciphertext, 48, 48)
}

// vaultUser is the vault identity of the caller: the signed-in user, or the
// user who created the API key (CLI).
func vaultUser(r *http.Request, tx pgx.Tx) (string, error) {
	p := principal(r)
	if p.APIKeyID == "" {
		if p.UserID == "" {
			return "", errf(http.StatusForbidden, "no user")
		}
		return p.UserID, nil
	}
	var uid string
	err := tx.QueryRow(r.Context(), `SELECT created_by FROM api_keys WHERE id=$1`, p.APIKeyID).Scan(&uid)
	if err != nil || uid == "" {
		return "", errf(http.StatusForbidden, "this API key has no owner; create a key in Settings → API Keys")
	}
	return uid, nil
}

func (s *Server) vaultMe(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		err = tx.QueryRow(r.Context(), `SELECT jsonb_build_object('user_id', user_id, 'public_key', public_key, 'wrapped_private', wrapped_private, 'created_at', created_at)
			FROM vault_members WHERE user_id=$1`, uid).Scan(&out)
		if errors.Is(err, pgx.ErrNoRows) {
			out = json.RawMessage("null")
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"member": out})
}

// putVaultMe registers (or resets) the caller's key pair. A reset makes every
// wrapped key unreadable, so the caller loses vault access until re-approved.
func (s *Server) putVaultMe(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		PublicKey      string                     `json:"public_key"`
		WrappedPrivate vaultcrypto.WrappedPrivate `json:"wrapped_private"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(body.PublicKey)
	if err == nil {
		_, err = ecdh.P256().NewPublicKey(raw)
	}
	wp := body.WrappedPrivate
	if err != nil || wp.Iterations < 100_000 || wp.Iterations > 10_000_000 || !validB64(wp.Salt, 16, 64) || !validB64(wp.IV, 12, 12) || !validB64(wp.Ciphertext, 100, 400) {
		return badRequest("public_key must be a P-256 point and wrapped_private a sealed PKCS#8 key")
	}
	p := principal(r)
	err = s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		wj, _ := json.Marshal(wp)
		var old string
		_ = tx.QueryRow(r.Context(), `SELECT public_key FROM vault_members WHERE user_id=$1`, uid).Scan(&old)
		if old != "" && old != body.PublicKey {
			if _, err := tx.Exec(r.Context(), `DELETE FROM vault_keys WHERE user_id=$1`, uid); err != nil {
				return err
			}
			auditDetail(r, "reset", true)
		}
		_, err = tx.Exec(r.Context(), `INSERT INTO vault_members (tenant_id, user_id, email, public_key, wrapped_private) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (tenant_id, user_id) DO UPDATE SET public_key=EXCLUDED.public_key, wrapped_private=EXCLUDED.wrapped_private, email=EXCLUDED.email`,
			p.TenantID, uid, firstNonEmpty(p.Email, p.Name), body.PublicKey, wj)
		return err
	})
	if err != nil {
		return err
	}
	return s.vaultMe(w, r)
}

// vaultState is the project vault as seen by the caller (metadata only).
func vaultState(r *http.Request, tx pgx.Tx, projectID, uid string, withCiphertext bool) (map[string]any, error) {
	ctx := r.Context()
	var name string
	if err := tx.QueryRow(ctx, `SELECT name FROM projects WHERE id=$1`, projectID).Scan(&name); err != nil {
		return nil, err
	}
	out := map[string]any{"project_id": projectID, "project": name, "initialized": false, "key_version": 0, "my_key": nil}
	var version int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(key_version), 0) FROM vault_keys WHERE project_id=$1`, projectID).Scan(&version); err != nil {
		return nil, err
	}
	out["initialized"], out["key_version"] = version > 0, version
	var mine json.RawMessage
	err := tx.QueryRow(ctx, `SELECT wrapped FROM vault_keys WHERE project_id=$1 AND user_id=$2`, projectID, uid).Scan(&mine)
	if err == nil {
		out["my_key"] = mine
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	cipher := `NULL::text, NULL::text`
	if withCiphertext && mine != nil {
		cipher = `i.iv, i.ciphertext`
	}
	items, err := one(ctx, tx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('id', i.id, 'name', i.name, 'kind', i.kind, 'version', i.version,
		'key_version', i.key_version, 'size', i.size, 'keys', (SELECT COALESCE(jsonb_agg(f->>'name'), '[]') FROM jsonb_array_elements(i.fingerprints) f),
		'updated_by', i.updated_by, 'updated_at', i.updated_at, 'iv', x.iv, 'ciphertext', x.ciphertext,
		'leaks', (SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_object('key', fp->>'name', 'pr', pr.number, 'repo', pr.repo_full_name,
				'file', f->>'file', 'line', f->'line', 'project_id', p.id)), '[]')
			FROM jsonb_array_elements(i.fingerprints) fp
			JOIN pr_reviews rv ON rv.findings @> jsonb_build_array(jsonb_build_object('fingerprint', fp->>'sha256'))
			CROSS JOIN jsonb_array_elements(rv.findings) f
			JOIN pull_requests pr ON pr.id = rv.pr_id LEFT JOIN projects p ON p.gh_repo_id = pr.repo_id
			WHERE f->>'fingerprint' = fp->>'sha256')) ORDER BY i.name), '[]')
		FROM vault_items i CROSS JOIN LATERAL (SELECT `+cipher+`) AS x(iv, ciphertext) WHERE i.project_id=$1`, projectID)
	if err != nil {
		return nil, err
	}
	out["items"] = items
	members, err := one(ctx, tx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('user_id', m.user_id, 'email', m.email, 'public_key', m.public_key,
		'has_access', k.user_id IS NOT NULL, 'key_version', k.key_version, 'granted_by', k.granted_by, 'granted_at', k.created_at) ORDER BY m.email), '[]')
		FROM vault_members m LEFT JOIN vault_keys k ON k.user_id = m.user_id AND k.project_id = $1`, projectID)
	if err != nil {
		return nil, err
	}
	out["members"] = members
	return out, nil
}

func (s *Server) getVault(w http.ResponseWriter, r *http.Request) error {
	var out map[string]any
	err := s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		out, err = vaultState(r, tx, r.PathValue("id"), uid, false)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// machineVault is the CLI's view: the vault of a project by name, with the
// ciphertext of every item (the CLI decrypts locally). Each fetch is audited.
func (s *Server) machineVault(w http.ResponseWriter, r *http.Request) error {
	name := r.URL.Query().Get("project")
	if name == "" {
		return badRequest("project is required (e.g. acme/web)")
	}
	var out map[string]any
	var member json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		var pid string
		if err := tx.QueryRow(r.Context(), `SELECT id FROM projects WHERE name=$1 ORDER BY created_at LIMIT 1`, name).Scan(&pid); err != nil {
			return err
		}
		if err := tx.QueryRow(r.Context(), `SELECT jsonb_build_object('user_id', user_id, 'public_key', public_key, 'wrapped_private', wrapped_private)
			FROM vault_members WHERE user_id=$1`, uid).Scan(&member); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errf(http.StatusForbidden, "set up your vault passphrase first: open the project's Secrets tab in depguard")
			}
			return err
		}
		out, err = vaultState(r, tx, pid, uid, true)
		if err == nil && out["my_key"] == nil {
			return errf(http.StatusForbidden, "you have no access to this project's vault yet: ask a teammate to approve you in the Secrets tab")
		}
		return err
	})
	if err != nil {
		return err
	}
	out["member"] = member
	s.writeAudit(r, auditEntry{Kind: "api_key", Action: "GET /v1/vault", TargetType: "project", TargetID: out["project_id"].(string),
		Details: map[string]any{"project": name, "items": "all"}})
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) initVault(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Wrapped vaultcrypto.WrappedKey `json:"wrapped"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if !validWrappedKey(body.Wrapped) {
		return badRequest("wrapped must be a vault key sealed for you")
	}
	p := principal(r)
	err := s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM vault_keys WHERE project_id=$1`, r.PathValue("id")).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return errf(http.StatusConflict, "this project's vault already exists; ask a member to approve you")
		}
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM vault_members WHERE user_id=$1`, uid).Scan(&n); err != nil || n == 0 {
			return badRequest("set up your vault passphrase first")
		}
		wj, _ := json.Marshal(body.Wrapped)
		_, err = tx.Exec(r.Context(), `INSERT INTO vault_keys (tenant_id, project_id, user_id, key_version, wrapped, granted_by) VALUES ($1,$2,$3,1,$4,$5)`,
			p.TenantID, r.PathValue("id"), uid, wj, firstNonEmpty(p.Email, p.Name))
		return err
	})
	if err != nil {
		return err
	}
	return s.getVault(w, r)
}

// grantVault gives a member access: the caller's browser wrapped the vault key for them.
func (s *Server) grantVault(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Wrapped    vaultcrypto.WrappedKey `json:"wrapped"`
		KeyVersion int                    `json:"key_version"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if !validWrappedKey(body.Wrapped) {
		return badRequest("wrapped must be the vault key sealed for this member")
	}
	p := principal(r)
	target := r.PathValue("user")
	auditDetail(r, "member", target)
	err := s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		var cur, mine int
		if err := tx.QueryRow(r.Context(), `SELECT COALESCE(max(key_version),0), COALESCE(max(key_version) FILTER (WHERE user_id=$2),0)
			FROM vault_keys WHERE project_id=$1`, r.PathValue("id"), uid).Scan(&cur, &mine); err != nil {
			return err
		}
		if mine == 0 || mine != cur || body.KeyVersion != cur {
			return errf(http.StatusConflict, "you need current access to this vault to approve someone (refresh the page)")
		}
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM vault_members WHERE user_id=$1`, target).Scan(&n); err != nil || n == 0 {
			return badRequest("this person has not set up a vault passphrase yet")
		}
		wj, _ := json.Marshal(body.Wrapped)
		_, err = tx.Exec(r.Context(), `INSERT INTO vault_keys (tenant_id, project_id, user_id, key_version, wrapped, granted_by) VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (project_id, user_id) DO UPDATE SET key_version=EXCLUDED.key_version, wrapped=EXCLUDED.wrapped, granted_by=EXCLUDED.granted_by, created_at=now()`,
			p.TenantID, r.PathValue("id"), target, cur, wj, firstNonEmpty(p.Email, p.Name))
		return err
	})
	if err != nil {
		return err
	}
	return s.getVault(w, r)
}

func (s *Server) revokeVault(w http.ResponseWriter, r *http.Request) error {
	auditDetail(r, "member", r.PathValue("user"))
	err := s.tx(r, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `DELETE FROM vault_keys WHERE project_id=$1 AND user_id=$2`, r.PathValue("id"), r.PathValue("user"))
		return err
	})
	if err != nil {
		return err
	}
	return s.getVault(w, r)
}

// rotateVault replaces the vault key: new grants for everyone who keeps
// access and every item re-encrypted, atomically (after removing a member).
func (s *Server) rotateVault(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		KeyVersion int `json:"key_version"`
		Grants     []struct {
			UserID  string                 `json:"user_id"`
			Wrapped vaultcrypto.WrappedKey `json:"wrapped"`
		} `json:"grants"`
		Items []struct {
			ID         string `json:"id"`
			IV         string `json:"iv"`
			Ciphertext string `json:"ciphertext"`
		} `json:"items"`
	}
	if err := decode(w, r, 64<<20, &body); err != nil {
		return err
	}
	p := principal(r)
	pid := r.PathValue("id")
	err := s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		var cur, mine, items int
		if err := tx.QueryRow(r.Context(), `SELECT COALESCE(max(key_version),0), COALESCE(max(key_version) FILTER (WHERE user_id=$2),0),
			(SELECT count(*) FROM vault_items WHERE project_id=$1) FROM vault_keys WHERE project_id=$1`, pid, uid).Scan(&cur, &mine, &items); err != nil {
			return err
		}
		if mine != cur || body.KeyVersion != cur+1 {
			return errf(http.StatusConflict, "the vault changed meanwhile; refresh and try again")
		}
		if len(body.Items) != items {
			return badRequest("every item must be re-encrypted with the new key")
		}
		keepsMe := false
		for _, g := range body.Grants {
			keepsMe = keepsMe || g.UserID == uid
			if !validWrappedKey(g.Wrapped) {
				return badRequest("invalid wrapped key for %s", g.UserID)
			}
		}
		if !keepsMe {
			return badRequest("keep your own access when rotating")
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM vault_keys WHERE project_id=$1`, pid); err != nil {
			return err
		}
		for _, g := range body.Grants {
			wj, _ := json.Marshal(g.Wrapped)
			if _, err := tx.Exec(r.Context(), `INSERT INTO vault_keys (tenant_id, project_id, user_id, key_version, wrapped, granted_by)
				SELECT $1,$2,$3,$4,$5,$6 WHERE EXISTS (SELECT 1 FROM vault_members WHERE user_id=$3)`,
				p.TenantID, pid, g.UserID, body.KeyVersion, wj, firstNonEmpty(p.Email, p.Name)); err != nil {
				return err
			}
		}
		for _, it := range body.Items {
			if !validB64(it.IV, 12, 12) || !validB64(it.Ciphertext, 16, vaultItemLimit) {
				return badRequest("invalid ciphertext for %s", it.ID)
			}
			tag, err := tx.Exec(r.Context(), `UPDATE vault_items SET iv=$3, ciphertext=$4, key_version=$5 WHERE id=$1 AND project_id=$2`,
				it.ID, pid, it.IV, it.Ciphertext, body.KeyVersion)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return badRequest("unknown item %s", it.ID)
			}
		}
		auditDetail(r, "key_version", body.KeyVersion)
		auditDetail(r, "members", len(body.Grants))
		return nil
	})
	if err != nil {
		return err
	}
	return s.getVault(w, r)
}

func (s *Server) putVaultItem(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Name         string `json:"name"`
		Kind         string `json:"kind"`
		IV           string `json:"iv"`
		Ciphertext   string `json:"ciphertext"`
		Size         int    `json:"size"`
		KeyVersion   int    `json:"key_version"`
		Fingerprints []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"fingerprints"`
	}
	if err := decode(w, r, vaultItemLimit, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if !vaultName.MatchString(body.Name) || (body.Kind != "env" && body.Kind != "file") || !validB64(body.IV, 12, 12) ||
		!validB64(body.Ciphertext, 16, vaultItemLimit) || len(body.Fingerprints) > 500 {
		return badRequest("name, kind (env|file), iv and ciphertext are required (files up to 1 MB)")
	}
	for _, f := range body.Fingerprints {
		if !sha256Hex.MatchString(f.SHA256) || len(f.Name) > 200 {
			return badRequest("fingerprints must be SHA-256 hex digests")
		}
	}
	p := principal(r)
	auditDetail(r, "item", body.Name)
	err := s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		var cur, mine int
		if err := tx.QueryRow(r.Context(), `SELECT COALESCE(max(key_version),0), COALESCE(max(key_version) FILTER (WHERE user_id=$2),0)
			FROM vault_keys WHERE project_id=$1`, r.PathValue("id"), uid).Scan(&cur, &mine); err != nil {
			return err
		}
		if mine == 0 || mine != cur || body.KeyVersion != cur {
			return errf(http.StatusConflict, "you need current access to this vault (refresh the page)")
		}
		var others int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM vault_items WHERE project_id=$1 AND name<>$2`, r.PathValue("id"), body.Name).Scan(&others); err != nil {
			return err
		}
		if others >= maxVaultItems {
			return badRequest("a project vault holds at most %d files", maxVaultItems)
		}
		fj, _ := json.Marshal(body.Fingerprints)
		if body.Fingerprints == nil {
			fj = []byte("[]")
		}
		who := firstNonEmpty(p.Email, p.Name)
		_, err = tx.Exec(r.Context(), `INSERT INTO vault_items (id, tenant_id, project_id, name, kind, key_version, iv, ciphertext, size, fingerprints, created_by, updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)
			ON CONFLICT (project_id, name) DO UPDATE SET kind=EXCLUDED.kind, key_version=EXCLUDED.key_version, iv=EXCLUDED.iv, ciphertext=EXCLUDED.ciphertext,
			  size=EXCLUDED.size, fingerprints=EXCLUDED.fingerprints, updated_by=EXCLUDED.updated_by, updated_at=now(), version=vault_items.version+1`,
			ids.New(), p.TenantID, r.PathValue("id"), body.Name, body.Kind, cur, body.IV, body.Ciphertext, body.Size, fj, who)
		return err
	})
	if err != nil {
		return err
	}
	return s.getVault(w, r)
}

// getVaultItem returns one item's ciphertext to a member with access; every read is audited.
func (s *Server) getVaultItem(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	var name string
	err := s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM vault_keys WHERE project_id=$1 AND user_id=$2`, r.PathValue("id"), uid).Scan(&n); err != nil || n == 0 {
			return errf(http.StatusForbidden, "you have no access to this vault")
		}
		return tx.QueryRow(r.Context(), `SELECT name, jsonb_build_object('id', id, 'name', name, 'kind', kind, 'version', version, 'key_version', key_version,
			'iv', iv, 'ciphertext', ciphertext, 'size', size) FROM vault_items WHERE id=$1 AND project_id=$2`, r.PathValue("item"), r.PathValue("id")).Scan(&name, &out)
	})
	if err != nil {
		return err
	}
	s.writeAudit(r, auditEntry{Kind: "user", Action: "GET /projects/{id}/vault/items/{item}", TargetType: "project", TargetID: r.PathValue("id"),
		Details: map[string]any{"item": name}})
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) deleteVaultItem(w http.ResponseWriter, r *http.Request) error {
	err := s.tx(r, func(tx pgx.Tx) error {
		var name string
		err := tx.QueryRow(r.Context(), `DELETE FROM vault_items WHERE id=$1 AND project_id=$2 RETURNING name`, r.PathValue("item"), r.PathValue("id")).Scan(&name)
		auditDetail(r, "item", name)
		return err
	})
	if err != nil {
		return err
	}
	return s.getVault(w, r)
}

// listVaults is the Secrets overview: every project with its vault status for the caller.
func (s *Server) listVaults(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		uid, err := vaultUser(r, tx)
		if err != nil {
			return err
		}
		out, err = one(r.Context(), tx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('project_id', p.id, 'project', p.name, 'source', p.source,
			'initialized', EXISTS (SELECT 1 FROM vault_keys k WHERE k.project_id = p.id),
			'has_access', EXISTS (SELECT 1 FROM vault_keys k WHERE k.project_id = p.id AND k.user_id = $1),
			'items', (SELECT count(*) FROM vault_items i WHERE i.project_id = p.id),
			'members', (SELECT count(*) FROM vault_keys k WHERE k.project_id = p.id),
			'leaks', (SELECT count(*) FROM vault_items i, jsonb_array_elements(i.fingerprints) fp
				WHERE i.project_id = p.id AND EXISTS (SELECT 1 FROM pr_reviews rv WHERE rv.findings @> jsonb_build_array(jsonb_build_object('fingerprint', fp->>'sha256')))),
			'updated_at', (SELECT max(updated_at) FROM vault_items i WHERE i.project_id = p.id))
			ORDER BY (SELECT count(*) FROM vault_items i WHERE i.project_id = p.id) DESC, p.name), '[]') FROM projects p`, uid)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": out})
}
