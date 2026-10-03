package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Inventory discovery is deliberately simple: well-known per-user locations only.
//
//	coding_agent   Claude Code (~/.claude), Cursor (~/.cursor), Windsurf (~/.codeium/windsurf),
//	               Codex (~/.codex), Gemini CLI (~/.gemini)
//	mcp_server     "mcpServers" in ~/.claude.json (+ per-project), ~/.cursor/mcp.json,
//	               ~/.codeium/windsurf/mcp_config.json, ~/.gemini/settings.json,
//	               ~/.config/Claude/claude_desktop_config.json; "servers" in VS Code's
//	               ~/.config/Code/User/mcp.json; [mcp_servers.<name>] in ~/.codex/config.toml
//	agent_skill    directories under ~/.claude/skills and ~/.codex/skills
//	ide_extension  ~/.vscode/extensions, ~/.cursor/extensions, ~/.windsurf/extensions
//	cli_tool       claude, codex, gemini, cursor-agent, pmg, gryph, vet on PATH
//
// MCP env/headers are never collected; args that look like secrets are dropped.

type invItem struct {
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	Version    string         `json:"version,omitempty"`
	Scope      string         `json:"scope,omitempty"`
	ConfigPath string         `json:"config_path"`
	Details    map[string]any `json:"details,omitempty"`
}

var codingAgents = []struct{ name, path string }{
	{"claude-code", ".claude"}, {"cursor", ".cursor"}, {"windsurf", ".codeium/windsurf"},
	{"codex", ".codex"}, {"gemini-cli", ".gemini"},
}

var mcpConfigs = []struct{ agent, path, key string }{
	{"claude-code", ".claude.json", "mcpServers"},
	{"cursor", ".cursor/mcp.json", "mcpServers"},
	{"windsurf", ".codeium/windsurf/mcp_config.json", "mcpServers"},
	{"gemini-cli", ".gemini/settings.json", "mcpServers"},
	{"claude-desktop", ".config/Claude/claude_desktop_config.json", "mcpServers"},
	{"vscode", ".config/Code/User/mcp.json", "servers"},
}

var (
	secretish  = regexp.MustCompile(`(?i)(token|secret|password|passwd|apikey|api_key|api-key|bearer|authorization)`)
	tokenLike  = regexp.MustCompile(`^(ghp_|gho_|ghs_|github_pat_|glpat-|sk-|xox[abp]-|AKIA)`)
	extVersion = regexp.MustCompile(`^(.+?)-(\d+\.\d+\.\d+[^/]*)$`)
	codexMCP   = regexp.MustCompile(`^\s*\[mcp_servers\.("?)([^"\]]+)("?)\]`)
)

func discover(home string) []invItem {
	items := []invItem{}
	add := func(it invItem) { items = append(items, it) }
	abs := func(p string) string { return filepath.Join(home, filepath.FromSlash(p)) }

	for _, a := range codingAgents {
		if _, err := os.Stat(abs(a.path)); err == nil {
			add(invItem{Kind: "coding_agent", Name: a.name, Scope: "system", ConfigPath: "~/" + a.path})
		}
	}
	for _, m := range mcpConfigs {
		b, err := os.ReadFile(abs(m.path))
		if err != nil {
			continue
		}
		var doc map[string]any
		if json.Unmarshal(b, &doc) != nil {
			continue
		}
		cfgPath := "~/" + m.path
		addServers(add, doc[m.key], m.agent, "system", cfgPath)
		if projects, ok := doc["projects"].(map[string]any); ok && m.agent == "claude-code" {
			for dir, p := range projects {
				if pm, ok := p.(map[string]any); ok {
					addServers(add, pm["mcpServers"], m.agent, "project", cfgPath+"#"+tildePath(home, dir))
				}
			}
		}
	}
	if f, err := os.Open(abs(".codex/config.toml")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if m := codexMCP.FindStringSubmatch(sc.Text()); m != nil {
				add(invItem{Kind: "mcp_server", Name: m[2], Scope: "system", ConfigPath: "~/.codex/config.toml",
					Details: map[string]any{"agent": "codex"}})
			}
		}
		f.Close()
	}
	for _, dir := range []string{".claude/skills", ".codex/skills"} {
		entries, _ := os.ReadDir(abs(dir))
		for _, e := range entries {
			if e.IsDir() {
				add(invItem{Kind: "agent_skill", Name: e.Name(), Scope: "system", ConfigPath: "~/" + dir + "/" + e.Name()})
			}
		}
	}
	for _, dir := range []string{".vscode/extensions", ".cursor/extensions", ".windsurf/extensions"} {
		entries, _ := os.ReadDir(abs(dir))
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			name, ver := e.Name(), ""
			if m := extVersion.FindStringSubmatch(name); m != nil {
				name, ver = m[1], m[2]
			}
			add(invItem{Kind: "ide_extension", Name: name, Version: ver, Scope: "system", ConfigPath: "~/" + dir,
				Details: map[string]any{"ide": strings.TrimPrefix(strings.Split(dir, "/")[0], ".")}})
		}
	}
	for _, bin := range []string{"claude", "codex", "gemini", "cursor-agent", "pmg", "gryph", "vet"} {
		if p, err := exec.LookPath(bin); err == nil {
			add(invItem{Kind: "cli_tool", Name: bin, Scope: "system", ConfigPath: tildePath(home, p)})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func addServers(add func(invItem), v any, agent, scope, cfgPath string) {
	servers, ok := v.(map[string]any)
	if !ok {
		return
	}
	for name, s := range servers {
		sm, _ := s.(map[string]any)
		d := map[string]any{"agent": agent}
		for _, k := range []string{"command", "url", "type"} {
			if str, ok := sm[k].(string); ok && !secretish.MatchString(str) {
				d[k] = str
			}
		}
		if args, ok := sm["args"].([]any); ok {
			var keep []string
			skipNext := false
			for _, a := range args {
				s, _ := a.(string)
				secret := secretish.MatchString(s) || tokenLike.MatchString(s) || strings.Contains(s, "=")
				if !secret && !skipNext {
					keep = append(keep, s)
				}
				skipNext = secret && strings.HasPrefix(s, "-") // value of a secret flag
			}
			d["args"] = keep
		}
		add(invItem{Kind: "mcp_server", Name: name, Scope: scope, ConfigPath: cfgPath, Details: d})
	}
}
