package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupAgents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir()) // no claude CLI
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/SKILL.md" {
			w.Write([]byte("---\nname: depguard\ndescription: x\n---\nserved by the depguard server\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer api.Close()
	t.Setenv("DEPGUARD_API_URL", api.URL)
	t.Setenv("DEPGUARD_API_KEY", "dg_testkey")
	var buf bytes.Buffer
	out = &buf
	write := func(rel, s string) {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(s), 0o600)
	}
	read := func(rel string) string { b, _ := os.ReadFile(filepath.Join(home, rel)); return string(b) }
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	write(".cursor/mcp.json", `{"mcpServers":{"other":{"url":"https://x"}}}`)
	write(".gemini/settings.json", `{"theme":"dark"}`)
	write(".codex/config.toml", "model = \"o4\"\n")
	write(".codeium/windsurf/mcp_config.json", "// comment\n{}")

	for i := 0; i < 2; i++ { // idempotent
		if err := runSetupAgents(nil); err != nil {
			t.Fatal(err)
		}
	}
	var cursor map[string]map[string]map[string]any
	json.Unmarshal([]byte(read(".cursor/mcp.json")), &cursor)
	if cursor["mcpServers"]["other"] == nil || cursor["mcpServers"]["depguard"]["url"] != api.URL+"/mcp" ||
		cursor["mcpServers"]["depguard"]["headers"].(map[string]any)["Authorization"] != "Bearer dg_testkey" {
		t.Fatalf("cursor: %s", read(".cursor/mcp.json"))
	}
	if cursor["mcpServers"]["depguard-secrets"]["args"].([]any)[0] != "mcp" {
		t.Fatalf("local secrets server missing: %s", read(".cursor/mcp.json"))
	}
	if g := read(".gemini/settings.json"); !strings.Contains(g, `"theme": "dark"`) || !strings.Contains(g, `"httpUrl": "`+api.URL+`/mcp"`) {
		t.Fatalf("gemini: %s", g)
	}
	codex := read(".codex/config.toml")
	if strings.Count(codex, "[mcp_servers.depguard-secrets]") != 1 || strings.Count(codex, "[mcp_servers.depguard]") != 1 || !strings.HasPrefix(codex, "model = \"o4\"") || !strings.Contains(codex, `url = "`+api.URL+`/mcp"`) {
		t.Fatalf("codex: %s", codex)
	}
	for _, s := range []string{".claude/skills/depguard/SKILL.md", ".codex/skills/depguard/SKILL.md"} {
		if !strings.Contains(read(s), "served by the depguard server") { // downloaded, not the built-in copy
			t.Fatalf("skill %s missing", s)
		}
	}
	if fi, _ := os.Stat(filepath.Join(home, ".cursor/mcp.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("config with the key must be private: %v", fi.Mode())
	}
	if read(".codeium/windsurf/mcp_config.json") != "// comment\n{}" || !strings.Contains(buf.String(), "not plain JSON") {
		t.Fatalf("JSONC file must be left alone: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "VS Code (Copilot)") || !strings.Contains(buf.String(), "not installed") {
		t.Fatalf("output: %s", buf.String())
	}

	if err := runSetupAgents([]string{"--remove"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read(".cursor/mcp.json"), "depguard") || strings.Contains(read(".gemini/settings.json"), "depguard") || !strings.Contains(read(".cursor/mcp.json"), "other") ||
		strings.Contains(read(".codex/config.toml"), "depguard") || !strings.Contains(read(".codex/config.toml"), "model") ||
		read(".claude/skills/depguard/SKILL.md") != "" {
		t.Fatalf("remove left: %s / %s", read(".cursor/mcp.json"), read(".codex/config.toml"))
	}
}
