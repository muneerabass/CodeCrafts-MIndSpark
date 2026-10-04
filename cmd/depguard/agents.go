package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/depguard/depguard/skills"
)

// AI coding agents that `depguard setup agents` connects to the depguard MCP
// server (and, where the agent supports skills, the depguard skill).
type agentTarget struct {
	name    string
	present func(home string) bool
	install func(home string, mcp mcpConn) (string, error) // returns what was done
	remove  func(home string) error
}

type mcpConn struct{ url, auth, bin string } // bin: this depguard binary, for the local secrets server

// fetchSkill downloads the current depguard skill from the server, falling
// back to the copy built into this CLI when the server is unreachable.
func fetchSkill(apiURL string) (string, string) {
	if apiURL != "" {
		cl := &http.Client{Timeout: 15 * time.Second}
		if res, err := cl.Get(strings.TrimRight(apiURL, "/") + "/agent/SKILL.md"); err == nil {
			defer res.Body.Close()
			b, _ := io.ReadAll(io.LimitReader(res.Body, 256<<10))
			if res.StatusCode == 200 && strings.HasPrefix(string(b), "---\nname: depguard") {
				return string(b), "from " + strings.TrimRight(apiURL, "/")
			}
		}
	}
	return skills.Depguard, "built-in copy (server unreachable)"
}

func agentTargets(skillMD string) []agentTarget {
	skill := func(dir string) func(home string) error {
		return func(home string) error {
			p := filepath.Join(home, dir, "depguard", "SKILL.md")
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			return writeFileAtomic(p, []byte(skillMD), 0o644)
		}
	}
	rmSkill := func(home, dir string) { _ = os.RemoveAll(filepath.Join(home, dir, "depguard")) }
	// Each agent gets the hosted server (package checks) and the local
	// depguard-secrets server (`depguard mcp`, end-to-end encrypted vault).
	jsonServer := func(rel func(home string) string, path []string, entry func(mcpConn) map[string]any) (func(string, mcpConn) (string, error), func(string) error) {
		local := append(append([]string{}, path[:len(path)-1]...), "depguard-secrets")
		return func(home string, c mcpConn) (string, error) {
				p := rel(home)
				if err := mergeJSON(p, path, entry(c)); err != nil {
					return "", err
				}
				e := map[string]any{"command": c.bin, "args": []string{"mcp"}}
				if path[0] == "servers" { // VS Code
					e["type"] = "stdio"
				}
				return "MCP servers in " + tilde(home, p), mergeJSON(p, local, e)
			}, func(home string) error {
				return errors.Join(mergeJSON(rel(home), path, nil), mergeJSON(rel(home), local, nil))
			}
	}
	vscodeDir := func(home string) string {
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", "Code", "User")
		case "windows":
			return filepath.Join(os.Getenv("APPDATA"), "Code", "User")
		}
		return filepath.Join(home, ".config", "Code", "User")
	}
	header := func(c mcpConn) map[string]any { return map[string]any{"Authorization": c.auth} }

	cursorIn, cursorRm := jsonServer(func(h string) string { return filepath.Join(h, ".cursor", "mcp.json") }, []string{"mcpServers", "depguard"},
		func(c mcpConn) map[string]any { return map[string]any{"url": c.url, "headers": header(c)} })
	vscodeIn, vscodeRm := jsonServer(func(h string) string { return filepath.Join(vscodeDir(h), "mcp.json") }, []string{"servers", "depguard"},
		func(c mcpConn) map[string]any {
			return map[string]any{"type": "http", "url": c.url, "headers": header(c)}
		})
	windsurfIn, windsurfRm := jsonServer(func(h string) string { return filepath.Join(h, ".codeium", "windsurf", "mcp_config.json") }, []string{"mcpServers", "depguard"},
		func(c mcpConn) map[string]any { return map[string]any{"serverUrl": c.url, "headers": header(c)} })
	geminiIn, geminiRm := jsonServer(func(h string) string { return filepath.Join(h, ".gemini", "settings.json") }, []string{"mcpServers", "depguard"},
		func(c mcpConn) map[string]any { return map[string]any{"httpUrl": c.url, "headers": header(c)} })

	return []agentTarget{
		{name: "Claude Code",
			present: func(h string) bool {
				_, err := exec.LookPath("claude")
				return err == nil || exists(filepath.Join(h, ".claude"))
			},
			install: func(h string, c mcpConn) (string, error) {
				if err := skill(".claude/skills")(h); err != nil {
					return "", err
				}
				bin, err := exec.LookPath("claude")
				if err != nil {
					return "skill installed; MCP needs the claude CLI: " + claudeAdd(c), nil
				}
				_ = exec.Command(bin, "mcp", "remove", "-s", "user", "depguard").Run()
				_ = exec.Command(bin, "mcp", "remove", "-s", "user", "depguard-secrets").Run()
				if out, err := exec.Command(bin, "mcp", "add", "-s", "user", "--transport", "http", "depguard", c.url, "--header", "Authorization: "+c.auth).CombinedOutput(); err != nil {
					return "", fmt.Errorf("claude mcp add: %v: %s", err, strings.TrimSpace(string(out)))
				}
				if out, err := exec.Command(bin, "mcp", "add", "-s", "user", "depguard-secrets", "--", c.bin, "mcp").CombinedOutput(); err != nil {
					return "", fmt.Errorf("claude mcp add depguard-secrets: %v: %s", err, strings.TrimSpace(string(out)))
				}
				return "MCP servers + skill", nil
			},
			remove: func(h string) error {
				rmSkill(h, ".claude/skills")
				if bin, err := exec.LookPath("claude"); err == nil {
					_ = exec.Command(bin, "mcp", "remove", "-s", "user", "depguard").Run()
					_ = exec.Command(bin, "mcp", "remove", "-s", "user", "depguard-secrets").Run()
				}
				return nil
			}},
		{name: "Cursor", present: func(h string) bool { return exists(filepath.Join(h, ".cursor")) }, install: cursorIn, remove: cursorRm},
		{name: "VS Code (Copilot)", present: func(h string) bool { return exists(vscodeDir(h)) }, install: vscodeIn, remove: vscodeRm},
		{name: "Windsurf", present: func(h string) bool { return exists(filepath.Join(h, ".codeium", "windsurf")) }, install: windsurfIn, remove: windsurfRm},
		{name: "Gemini CLI", present: func(h string) bool { return exists(filepath.Join(h, ".gemini")) }, install: geminiIn, remove: geminiRm},
		{name: "Codex", present: func(h string) bool { return exists(filepath.Join(h, ".codex")) },
			install: func(h string, c mcpConn) (string, error) {
				if err := skill(".codex/skills")(h); err != nil {
					return "", err
				}
				p := filepath.Join(h, ".codex", "config.toml")
				return "MCP servers in " + tilde(h, p) + " + skill", setTOMLBlock(p, fmt.Sprintf("[mcp_servers.depguard]\nurl = %q\nhttp_headers = { \"Authorization\" = %q }\n\n[mcp_servers.depguard-secrets]\ncommand = %q\nargs = [\"mcp\"]\n", c.url, c.auth, c.bin))
			},
			remove: func(h string) error {
				rmSkill(h, ".codex/skills")
				return setTOMLBlock(filepath.Join(h, ".codex", "config.toml"), "")
			}},
	}
}

func claudeAdd(c mcpConn) string {
	return fmt.Sprintf("claude mcp add -s user --transport http depguard %s --header \"Authorization: Bearer <api-key>\"", c.url)
}

func tilde(home, p string) string {
	if r, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(r, "..") {
		return "~/" + filepath.ToSlash(r)
	}
	return p
}

// mergeJSON sets (or with v == nil deletes) obj[path...] in a JSON config
// file, keeping everything else. Files that are not plain JSON (comments) are
// left alone with an error, never overwritten.
func mergeJSON(p string, path []string, v map[string]any) error {
	root := map[string]any{}
	b, err := os.ReadFile(p)
	switch {
	case err == nil && len(strings.TrimSpace(string(b))) > 0:
		if err := json.Unmarshal(b, &root); err != nil {
			return fmt.Errorf("%s is not plain JSON (comments?), add the depguard server by hand: %w", p, err)
		}
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return err
	case v == nil:
		return nil // nothing to remove
	}
	m := root
	for _, k := range path[:len(path)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			if v == nil {
				return nil
			}
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
	last := path[len(path)-1]
	if v == nil {
		if _, ok := m[last]; !ok {
			return nil
		}
		delete(m, last)
	} else {
		m[last] = v
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(root, "", "  ")
	return writeFileAtomic(p, append(out, '\n'), 0o600) // holds the API key
}

const tomlStart, tomlEnd = "# >>> depguard (managed by `depguard setup agents`)", "# <<< depguard"

// setTOMLBlock replaces (or with body "" removes) depguard's marked block.
func setTOMLBlock(p, body string) error {
	b, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s := string(b)
	if i := strings.Index(s, tomlStart); i >= 0 {
		if j := strings.Index(s[i:], tomlEnd); j >= 0 {
			s = strings.TrimRight(s[:i], "\n") + "\n" + strings.TrimLeft(s[i+j+len(tomlEnd):], "\n")
		}
	} else if body != "" && strings.Contains(s, "[mcp_servers.depguard]") {
		return fmt.Errorf("%s already has an unmanaged [mcp_servers.depguard] table; remove it first", p)
	}
	if body != "" {
		s = strings.TrimRight(s, "\n") + "\n\n" + tomlStart + "\n" + body + tomlEnd + "\n"
	}
	if strings.TrimSpace(s) == "" && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(p, []byte(strings.TrimLeft(s, "\n")), 0o600)
}

// runSetupAgents connects every installed AI coding agent to depguard.
func runSetupAgents(args []string) error {
	fs := flag.NewFlagSet("setup agents", flag.ExitOnError)
	remove := fs.Bool("remove", false, "disconnect depguard from every agent")
	printOnly := fs.Bool("print", false, "print the configuration for any MCP client, change nothing")
	apiURL, apiKey := addClientFlags(fs)
	_ = fs.Parse(args)
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if *remove {
		targets := agentTargets("")
		for _, t := range targets {
			if err := t.remove(home); err != nil {
				fmt.Fprintf(out, "  %s %-18s %v\n", yellow("!"), t.name, err)
			}
		}
		fmt.Fprintf(out, "%s disconnected from your AI agents. Restart them to apply.\n", brand())
		return nil
	}
	c, err := resolveClient(*apiURL, *apiKey, nil)
	if err != nil {
		return err
	}
	if c.key == "" {
		return errors.New("no API key: run `depguard login` first (create a key in depguard → Settings → API Keys)")
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	if r, err := filepath.EvalSymlinks(bin); err == nil {
		bin = r
	}
	conn := mcpConn{url: strings.TrimRight(c.base, "/") + "/mcp", auth: "Bearer " + c.key, bin: bin}
	if *printOnly {
		fmt.Fprintf(out, "MCP server (streamable HTTP)\n  URL:    %s\n  Header: Authorization: Bearer <your API key>\n\nSkill: %s/agent/SKILL.md\n\nClaude Code:\n  %s\n",
			conn.url, strings.TrimRight(c.base, "/"), claudeAdd(conn))
		return nil
	}
	skillMD, from := fetchSkill(c.base)
	targets := agentTargets(skillMD)
	fmt.Fprintf(out, "%s connecting your AI coding agents (skill %s)\n", brand(), from)
	n := 0
	for _, t := range targets {
		if !t.present(home) {
			fmt.Fprintf(out, "  %s %-18s %s\n", dim("·"), t.name, dim("not installed"))
			continue
		}
		what, err := t.install(home, conn)
		if err != nil {
			fmt.Fprintf(out, "  %s %-18s %v\n", red("✖"), t.name, err)
			continue
		}
		n++
		fmt.Fprintf(out, "  %s %-18s %s\n", green("✓"), t.name, what)
	}
	if n == 0 {
		fmt.Fprintf(out, "\nNo supported agent found. For any other MCP client run: depguard setup agents --print\n")
		return nil
	}
	fmt.Fprintf(out, "\nRestart the agents (or reload MCP servers). They now check every package with depguard before installing it.\n")
	return nil
}
