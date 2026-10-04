package httpapi

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"strings"
	"testing"

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/vaultcrypto"
)

func TestVault(t *testing.T) {
	ctx := context.Background()
	_, err := tdb.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain) VALUES ('tv','v.test'), ('tv2','v2.test');
INSERT INTO projects (id, tenant_id, source, name, url, gh_repo_id) VALUES ('pv','tv','github','acme/pay','',901);`)
	if err != nil {
		t.Fatal(err)
	}
	owner, member, other := token("tv", "owner", false), token("tv", "member", false), token("tv2", "owner", false)
	register := func(tok, pass string) (*ecdh.PrivateKey, string) {
		t.Helper()
		priv, pub, wp, err := vaultcrypto.NewMember(pass)
		if err != nil {
			t.Fatal(err)
		}
		expect(t, do(t, "PUT", "/api/v1/vault/me", tok, map[string]any{"public_key": pub, "wrapped_private": wp}), 200)
		return priv, pub
	}
	if m := expect(t, do(t, "GET", "/api/v1/vault/me", owner, nil), 200).body; m["member"] != nil {
		t.Fatal("no member yet")
	}
	expect(t, do(t, "PUT", "/api/v1/vault/me", owner, map[string]any{"public_key": "bm90LWEta2V5", "wrapped_private": map[string]any{}}), 400)
	ownerPriv, ownerPub := register(owner, "owner pass")

	// Owner creates the project vault and stores a .env.
	vk := make([]byte, 32)
	copy(vk, "0123456789abcdef0123456789abcdef")
	wk, _ := vaultcrypto.WrapKey(vk, ownerPub, "pv", "u-owner")
	expect(t, do(t, "POST", "/api/v1/projects/pv/vault/init", member, map[string]any{"wrapped": wk}), 403) // admins only
	st := expect(t, do(t, "POST", "/api/v1/projects/pv/vault/init", owner, map[string]any{"wrapped": wk}), 200).body
	if st["initialized"] != true || st["key_version"].(float64) != 1 || st["my_key"] == nil {
		t.Fatalf("init %v", st)
	}
	expect(t, do(t, "POST", "/api/v1/projects/pv/vault/init", owner, map[string]any{"wrapped": wk}), 409)
	env := "STRIPE_KEY=sk_live_0123456789abcdef\nDEBUG=1\n"
	iv, ct, _ := vaultcrypto.EncryptItem(vk, []byte(env), "pv", ".env.production")
	fp := vaultcrypto.Fingerprint("sk_live_0123456789abcdef")
	st = expect(t, do(t, "PUT", "/api/v1/projects/pv/vault/items", owner, map[string]any{"name": ".env.production", "kind": "env", "iv": iv, "ciphertext": ct,
		"size": len(env), "key_version": 1, "fingerprints": []map[string]string{{"name": "STRIPE_KEY", "sha256": fp}}}), 200).body
	item := mapOf(listOf(st["items"])[0])
	if item["name"] != ".env.production" || item["ciphertext"] != nil || string(mustJSON(item["keys"])) != `["STRIPE_KEY"]` {
		t.Fatalf("item metadata %v", item)
	}
	if raw := do(t, "GET", "/api/v1/projects/pv/vault", owner, nil).raw; strings.Contains(raw, ct) || strings.Contains(raw, "sk_live") {
		t.Fatal("metadata endpoint leaked ciphertext or plaintext")
	}

	// A member without access sees metadata but can't fetch the ciphertext until approved.
	memberPriv, memberPub := register(member, "member pass")
	itemPath := "/api/v1/projects/pv/vault/items/" + item["id"].(string)
	expect(t, do(t, "GET", itemPath, member, nil), 403)
	mk, _ := vaultcrypto.WrapKey(vk, memberPub, "pv", "u-member")
	expect(t, do(t, "PUT", "/api/v1/projects/pv/vault/grants/u-member", owner, map[string]any{"wrapped": mk, "key_version": 1}), 200)
	ms := expect(t, do(t, "GET", "/api/v1/projects/pv/vault", member, nil), 200).body
	var myKey vaultcrypto.WrappedKey
	b, _ := json.Marshal(ms["my_key"])
	json.Unmarshal(b, &myKey)
	got, err := vaultcrypto.UnwrapKey(memberPriv, myKey, "pv", "u-member")
	if err != nil {
		t.Fatal(err)
	}
	it := expect(t, do(t, "GET", itemPath, member, nil), 200).body
	pt, err := vaultcrypto.DecryptItem(got, it["iv"].(string), it["ciphertext"].(string), "pv", ".env.production")
	if err != nil || string(pt) != env {
		t.Fatalf("member decrypt: %v %q", err, pt)
	}
	expect(t, do(t, "GET", "/api/v1/projects/pv/vault", other, nil), 404) // other tenant

	// Leak response: a PR finding with the same fingerprint points at the vault entry.
	if _, err := tdb.Owner.Exec(ctx, `INSERT INTO pull_requests (id, tenant_id, repo_id, repo_full_name, number, title, state, head_sha) VALUES ('prv','tv',901,'acme/pay',7,'oops','open','hv')`); err != nil {
		t.Fatal(err)
	}
	_, err = tdb.Owner.Exec(ctx, `INSERT INTO pr_reviews (id, tenant_id, pr_id, head_sha, findings) VALUES ('rvv','tv','prv','hv', $1)`,
		`[{"source":"rules","file":"config.js","line":3,"severity":"critical","category":"secrets","title":"API token committed","fingerprint":"`+fp+`"}]`)
	if err != nil {
		t.Fatal(err)
	}
	pr := expect(t, do(t, "GET", "/api/v1/projects/pv/pull-requests/7", owner, nil), 200).body
	vm := listOf(pr["vault_matches"])
	if len(vm) != 1 || mapOf(vm[0])["key"] != "STRIPE_KEY" || mapOf(vm[0])["item"] != ".env.production" {
		t.Fatalf("vault matches %v", pr["vault_matches"])
	}
	if leaks := listOf(mapOf(listOf(expect(t, do(t, "GET", "/api/v1/projects/pv/vault", owner, nil), 200).body["items"])[0])["leaks"]); len(leaks) != 1 || mapOf(leaks[0])["pr"].(float64) != 7 {
		t.Fatalf("leaks %v", leaks)
	}

	// Removing the member: revoke + rotate re-encrypts everything for the owner only.
	expect(t, do(t, "DELETE", "/api/v1/projects/pv/vault/grants/u-member", owner, nil), 200)
	vk2 := []byte("fedcba9876543210fedcba9876543210")
	wk2, _ := vaultcrypto.WrapKey(vk2, ownerPub, "pv", "u-owner")
	iv2, ct2, _ := vaultcrypto.EncryptItem(vk2, []byte(env), "pv", ".env.production")
	expect(t, do(t, "POST", "/api/v1/projects/pv/vault/rotate", owner, map[string]any{"key_version": 2, "grants": []any{map[string]any{"user_id": "u-owner", "wrapped": wk2}}, "items": []any{}}), 400)
	expect(t, do(t, "POST", "/api/v1/projects/pv/vault/rotate", owner, map[string]any{"key_version": 2, "grants": []any{map[string]any{"user_id": "u-owner", "wrapped": wk2}},
		"items": []any{map[string]any{"id": item["id"], "iv": iv2, "ciphertext": ct2}}}), 200)
	expect(t, do(t, "GET", itemPath, member, nil), 403)
	ost := expect(t, do(t, "GET", "/api/v1/projects/pv/vault", owner, nil), 200).body
	b, _ = json.Marshal(ost["my_key"])
	json.Unmarshal(b, &myKey)
	if k, err := vaultcrypto.UnwrapKey(ownerPriv, myKey, "pv", "u-owner"); err != nil || string(k) != string(vk2) {
		t.Fatalf("owner after rotation: %v", err)
	}

	if l := listOf(expect(t, do(t, "GET", "/api/v1/vaults", owner, nil), 200).body["items"]); len(l) != 1 || mapOf(l[0])["items"].(float64) != 1 || mapOf(l[0])["has_access"] != true || mapOf(l[0])["leaks"].(float64) != 1 {
		t.Fatalf("vaults overview %v", l)
	}

	// CLI (API key of the owner): the whole vault with ciphertext, audited.
	k, err := auth.CreateKey(ctx, tdb.App, "tv", "u-owner", "cli", nil)
	if err != nil {
		t.Fatal(err)
	}
	mv := expect(t, do(t, "GET", "/v1/vault?project=acme/pay", k.Key, nil), 200).body
	if mapOf(listOf(mv["items"])[0])["ciphertext"] != ct2 || mv["member"] == nil {
		t.Fatalf("machine vault %v", mv)
	}
	var n int
	tdb.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id='tv' AND action IN ('GET /v1/vault','GET /projects/{id}/vault/items/{item}')`).Scan(&n)
	if n != 2 {
		t.Fatalf("audited reads: %d", n)
	}
}
