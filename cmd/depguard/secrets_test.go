package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/depguard/depguard/internal/vaultcrypto"
	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

// fakeVault serves /v1/vault for one member with one .env and one file item.
func fakeVault(t *testing.T) *httptest.Server {
	_, pub, wp, err := vaultcrypto.NewMember("pass phrase")
	if err != nil {
		t.Fatal(err)
	}
	vk := []byte("0123456789abcdef0123456789abcdef")
	wk, _ := vaultcrypto.WrapKey(vk, pub, "p1", "u1")
	env := "API_TOKEN=tok_0123456789abcdef\nDB_URL='postgres://u:secretpw@db/app'\n"
	iv1, ct1, _ := vaultcrypto.EncryptItem(vk, []byte(env), "p1", ".env")
	iv2, ct2, _ := vaultcrypto.EncryptItem(vk, []byte(`{"private_key":"x"}`), "p1", "gcp-sa.json")
	member := map[string]any{"user_id": "u1", "public_key": pub, "wrapped_private": wp}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dg_k" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/v1/vault/me":
			json.NewEncoder(w).Encode(map[string]any{"member": member})
		case "/v1/vault":
			if r.URL.Query().Get("project") != "acme/app" {
				w.WriteHeader(404)
				w.Write([]byte(`{"error":"not found"}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"project_id": "p1", "project": "acme/app", "my_key": wk, "member": member,
				"items": []any{map[string]any{"id": "i1", "name": ".env", "kind": "env", "keys": []string{"API_TOKEN", "DB_URL"}, "iv": iv1, "ciphertext": ct1},
					map[string]any{"id": "i2", "name": "gcp-sa.json", "kind": "file", "iv": iv2, "ciphertext": ct2}}})
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestSecrets(t *testing.T) {
	srv := fakeVault(t)
	defer srv.Close()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("DEPGUARD_API_URL", srv.URL)
	t.Setenv("DEPGUARD_API_KEY", "dg_k")
	var buf bytes.Buffer
	out = &buf

	// Locked: the agent tool refuses and says how to unlock.
	c, _ := resolveClient("", "", nil)
	if _, err := openVault(c, "acme/app", false); err == nil || !strings.Contains(err.Error(), "secrets unlock") {
		t.Fatalf("locked: %v", err)
	}
	t.Setenv("DEPGUARD_VAULT_PASSPHRASE", "wrong")
	if code, err := runSecrets([]string{"unlock"}); err == nil || code == 0 {
		t.Fatal("wrong passphrase unlocked the vault")
	}
	t.Setenv("DEPGUARD_VAULT_PASSPHRASE", "pass phrase")
	if code, err := runSecrets([]string{"unlock", "--ttl", "1h"}); err != nil || code != 0 {
		t.Fatalf("unlock: %v", err)
	}
	if fi, _ := os.Stat(sessionPath()); fi.Mode().Perm() != 0o600 {
		t.Fatalf("session file mode %v", fi.Mode())
	}
	t.Setenv("DEPGUARD_VAULT_PASSPHRASE", "")

	// secrets run injects env vars and file secrets.
	res := filepath.Join(t.TempDir(), "out")
	code, err := runSecrets([]string{"run", "--project", "acme/app", "--", "sh", "-c", `printf "%s|%s|" "$API_TOKEN" "$DB_URL" > ` + res + ` && cat "$DEPGUARD_SECRETS_DIR/gcp-sa.json" >> ` + res})
	got, _ := os.ReadFile(res)
	if err != nil || code != 0 || string(got) != `tok_0123456789abcdef|postgres://u:secretpw@db/app|{"private_key":"x"}` {
		t.Fatalf("run: %v %d %q", err, code, got)
	}
	if code, _ := runSecrets([]string{"run", "--project", "acme/app", "--", "sh", "-c", "exit 3"}); code != 3 {
		t.Fatalf("exit code passthrough: %d", code)
	}

	// Agents: run_with_secrets masks every value in the output.
	mc, err := mcpclient.NewInProcessClient(newLocalMCP(c))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mc.Start(ctx)
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	if _, err := mc.Initialize(ctx, init); err != nil {
		t.Fatal(err)
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "run_with_secrets"
	req.Params.Arguments = map[string]any{"command": `echo "token=$API_TOKEN url=$DB_URL"; env | grep -c API_TOKEN; exit 4`, "project": "acme/app"}
	r, err := mc.CallTool(ctx, req)
	if err != nil || r.IsError {
		t.Fatalf("run_with_secrets: %v %+v", err, r)
	}
	text := r.Content[0].(mcp.TextContent).Text
	if strings.Contains(text, "tok_0123456789abcdef") || strings.Contains(text, "secretpw") ||
		!strings.Contains(text, "token=«API_TOKEN» url=«DB_URL»") || !strings.HasPrefix(text, "exit code 4") {
		t.Fatalf("masked output: %q", text)
	}
	req.Params.Name, req.Params.Arguments = "list_secrets", map[string]any{"project": "acme/app"}
	r, _ = mc.CallTool(ctx, req)
	if lt := r.Content[0].(mcp.TextContent).Text; !strings.Contains(lt, ".env (env): API_TOKEN, DB_URL") || strings.Contains(lt, "tok_") {
		t.Fatalf("list: %q", lt)
	}

	if _, err := runSecrets([]string{"lock"}); err != nil {
		t.Fatal(err)
	}
	if _, err := openVault(c, "acme/app", false); err == nil {
		t.Fatal("still unlocked after lock")
	}
}
