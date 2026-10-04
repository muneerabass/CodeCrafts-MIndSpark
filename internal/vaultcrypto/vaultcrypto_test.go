package vaultcrypto

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

type vectors struct {
	Passphrase     string                          `json:"passphrase"`
	PublicKey      string                          `json:"public_key"`
	WrappedPrivate WrappedPrivate                  `json:"wrapped_private"`
	WrappedKey     WrappedKey                      `json:"wrapped_key"`
	Item           struct{ IV, Ciphertext string } `json:"item"`
	Env            string                          `json:"env"`
	Parsed         []struct{ Key, Value string }   `json:"parsed"`
	Fingerprints   []struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	} `json:"fingerprints"`
}

func fingerprintsOf(env string) []map[string]string {
	var out []map[string]string
	for _, v := range SecretValues(ParseEnv(env)) {
		out = append(out, map[string]string{"name": v.Key, "sha256": Fingerprint(v.Value)})
	}
	return out
}

// TestBrowserVectors decrypts data produced by web/lib/vault-crypto.ts.
func TestBrowserVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/js_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapPrivate(v.WrappedPrivate, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	priv, err := UnwrapPrivate(v.WrappedPrivate, v.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if b64.EncodeToString(priv.PublicKey().Bytes()) != v.PublicKey {
		t.Fatal("public key mismatch")
	}
	vk, err := UnwrapKey(priv, v.WrappedKey, "proj1", "user1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapKey(priv, v.WrappedKey, "proj1", "someone-else"); err == nil {
		t.Fatal("key unwrapped for another user")
	}
	pt, err := DecryptItem(vk, v.Item.IV, v.Item.Ciphertext, "proj1", ".env.production")
	if err != nil || string(pt) != v.Env {
		t.Fatalf("item: %v %q", err, pt)
	}
	if _, err := DecryptItem(vk, v.Item.IV, v.Item.Ciphertext, "proj1", ".env.staging"); err == nil {
		t.Fatal("item decrypted under another name")
	}
	var parsed []struct{ Key, Value string }
	for _, e := range ParseEnv(v.Env) {
		parsed = append(parsed, struct{ Key, Value string }{e.Key, e.Value})
	}
	if !reflect.DeepEqual(parsed, v.Parsed) {
		t.Fatalf("parseEnv differs from the browser:\n go %q\n js %q", parsed, v.Parsed)
	}
	fp, _ := json.Marshal(fingerprintsOf(v.Env))
	js, _ := json.Marshal(v.Fingerprints)
	if string(fp) != string(js) {
		t.Fatalf("fingerprints differ:\n go %s\n js %s", fp, js)
	}
}

// TestWriteGoVectors writes data for scripts/vault-vectors.ts verify (WRITE_VECTORS=1).
func TestWriteGoVectors(t *testing.T) {
	if os.Getenv("WRITE_VECTORS") == "" {
		t.Skip("set WRITE_VECTORS=1")
	}
	js, _ := os.ReadFile("testdata/js_vectors.json")
	var src vectors
	json.Unmarshal(js, &src)
	_, pub, wp, err := NewMember("go passphrase ✓")
	if err != nil {
		t.Fatal(err)
	}
	vk := make([]byte, 32)
	for i := range vk {
		vk[i] = byte(i)
	}
	wk, err := WrapKey(vk, pub, "proj1", "user1")
	if err != nil {
		t.Fatal(err)
	}
	iv, ct, err := EncryptItem(vk, []byte(src.Env), "proj1", ".env.production")
	if err != nil {
		t.Fatal(err)
	}
	var parsed []map[string]string
	for _, e := range ParseEnv(src.Env) {
		parsed = append(parsed, map[string]string{"key": e.Key, "value": e.Value})
	}
	out, _ := json.MarshalIndent(map[string]any{"passphrase": "go passphrase ✓", "public_key": pub, "wrapped_private": wp, "wrapped_key": wk,
		"item": map[string]string{"iv": iv, "ciphertext": ct}, "env": src.Env, "parsed": parsed, "fingerprints": fingerprintsOf(src.Env)}, "", "  ")
	os.WriteFile("testdata/go_vectors.json", append(out, '\n'), 0o644)
}
