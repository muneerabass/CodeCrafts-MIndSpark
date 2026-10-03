package main

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFindLockfiles(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{"package-lock.json", "web/yarn.lock", "node_modules/x/package-lock.json", "vendor/go.mod",
		"svc/go.mod", ".github/workflows/ci.yml", ".hidden/poetry.lock", "README.md"} {
		write(t, root, f, "x")
	}
	got, err := findLockfiles(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".github/workflows/ci.yml", "package-lock.json", "svc/go.mod", "web/yarn.lock"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestScanCommand(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app/package-lock.json", "{}")
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dg_test" || r.URL.Path != "/v1/scans" || r.URL.Query().Get("wait") != "true" {
			http.Error(w, `{"error":"bad"}`, 400)
			return
		}
		_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			_, dp, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
			if p.FormName() == "lockfile" {
				paths = append(paths, dp["filename"])
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"scan_id": "S1", "status": "success", "conclusion": "failure", "report_md": "## bad", "url": "u"})
	}))
	defer srv.Close()
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("BITBUCKET_BUILD_NUMBER", "")
	code, err := runScan([]string{"--api-url", srv.URL, "--api-key", "dg_test", "--dir", root, "--fail-on-violation", "--project", "p", "--version", "v"})
	if err != nil || code != 1 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !slices.Equal(paths, []string{"app/package-lock.json"}) {
		t.Fatalf("uploaded %v", paths)
	}
	if code, err := runScan([]string{"--api-url", srv.URL, "--api-key", "dg_test", "--dir", root, "--project", "p", "--version", "v"}); err != nil || code != 0 {
		t.Fatalf("without --fail-on-violation: code=%d err=%v", code, err)
	}
}

func TestReadNewLines(t *testing.T) {
	f := filepath.Join(t.TempDir(), "20250101-pmg.log")
	os.WriteFile(f, []byte("{\"a\":1}\n{\"b\":2}\n{\"partial"), 0o644)
	chunk, off, err := readNewLines(f, 0, 1<<20)
	if err != nil || string(chunk) != "{\"a\":1}\n{\"b\":2}\n" || off != 16 {
		t.Fatalf("%q %d %v", chunk, off, err)
	}
	if chunk, off2, _ := readNewLines(f, off, 1<<20); len(chunk) != 0 || off2 != off {
		t.Fatalf("partial line shipped: %q", chunk)
	}
	os.WriteFile(f, []byte("{\"c\":3}\n"), 0o644) // truncated/rotated
	if chunk, _, _ := readNewLines(f, off, 1<<20); string(chunk) != "{\"c\":3}\n" {
		t.Fatalf("truncation: %q", chunk)
	}
}

func TestDiscover(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".claude/skills/pdf/SKILL.md", "x")
	write(t, home, ".claude.json", `{"mcpServers":{"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github","--token","abc123","ghp_zzz"],"env":{"GITHUB_TOKEN":"ghp_x"}}},
		"projects":{"`+home+`/proj":{"mcpServers":{"db":{"type":"http","url":"http://localhost:1"}}}}}`)
	write(t, home, ".cursor/mcp.json", `{"mcpServers":{"fs":{"command":"mcp-fs"}}}`)
	write(t, home, ".codex/config.toml", "[mcp_servers.docs]\ncommand = \"x\"\n")
	write(t, home, ".vscode/extensions/ms-python.python-2024.1.0-linux-x64/package.json", "{}")
	items := discover(home)
	var got []string
	for _, it := range items {
		got = append(got, it.Kind+":"+it.Name+"@"+it.Version)
	}
	for _, want := range []string{"coding_agent:claude-code@", "coding_agent:cursor@", "coding_agent:codex@",
		"mcp_server:github@", "mcp_server:db@", "mcp_server:fs@", "mcp_server:docs@", "agent_skill:pdf@",
		"ide_extension:ms-python.python@2024.1.0-linux-x64"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	b, _ := json.Marshal(items)
	if strings.Contains(string(b), "ghp_") || strings.Contains(string(b), "abc123") || strings.Contains(string(b), home) {
		t.Fatalf("secret or home path leaked: %s", b)
	}
}
