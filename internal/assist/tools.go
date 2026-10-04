// Package assist answers questions about a depguard workspace. The same tools
// back the dashboard's "Ask depguard" popup and the hosted MCP server.
//
// Tools read the REST API in-process as the asking user (auth.WithInternal), so
// every role check and query the dashboard uses applies unchanged. Long-tail
// questions run read-only SQL as depguard_ai (q_* views only).
package assist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/engine"
	"github.com/depguard/depguard/internal/llm"
	"github.com/depguard/depguard/internal/query"
)

// Env is who is asking and what the tools may use.
type Env struct {
	P     *auth.Principal // Role "" (API keys) is treated as member
	API   http.Handler    // the REST API (/api/v1/...)
	SQL   *query.Executor // Role depguard_ai
	Check func(ctx context.Context, tenant string, req engine.CheckRequest) (*engine.CheckResult, error)
}

func (e Env) admin() bool { return e.P != nil && e.P.CanWrite() }

// Tool is one read-only capability.
type Tool struct {
	Name, Description string
	Params            map[string]any // JSON-schema properties
	Required          []string
	Admin             bool // owner/admin only; never offered over MCP
	NoMCP             bool // MCP already has its own version
	Label             string
	Run               func(ctx context.Context, e Env, args map[string]any) (any, error)
}

// Spec is the tool as the model sees it.
func (t Tool) Spec() llm.Tool {
	props := t.Params
	if props == nil {
		props = map[string]any{}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(t.Required) > 0 {
		s["required"] = t.Required
	}
	return llm.Tool{Name: t.Name, Description: t.Description, Schema: s}
}

// For returns the tools e may use.
func For(e Env, mcp bool) []Tool {
	var out []Tool
	for _, t := range Tools {
		if (t.Admin && (mcp || !e.admin())) || (mcp && t.NoMCP) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// Find returns the tool by name among those e may use.
func Find(e Env, mcp bool, name string) (Tool, bool) {
	for _, t := range For(e, mcp) {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }

var pageParam = num("Page number (20 items per page), default 1")

// get makes a tool that reads one API path; {name} in path is filled from the
// argument of that name and other arguments become query parameters.
func get(name, label, desc, path string, params map[string]any, required ...string) Tool {
	return Tool{Name: name, Label: label, Description: desc, Params: params, Required: required,
		Run: func(ctx context.Context, e Env, args map[string]any) (any, error) {
			p := path
			q := url.Values{}
			for k, v := range args {
				s := strings.TrimSpace(fmt.Sprint(v))
				if s == "" || v == nil {
					continue
				}
				if f, ok := v.(float64); ok {
					s = fmt.Sprint(int64(f))
				}
				if strings.Contains(p, "{"+k+"}") {
					p = strings.ReplaceAll(p, "{"+k+"}", url.PathEscape(s))
				} else if _, known := params[k]; known {
					q.Set(k, s)
				}
			}
			if strings.Contains(p, "{") {
				return nil, fmt.Errorf("missing argument for %s", p)
			}
			return Call(ctx, e, http.MethodGet, p, q)
		}}
}

// Call reads /api/v1+path as e.P.
func Call(ctx context.Context, e Env, method, path string, q url.Values) (json.RawMessage, error) {
	p := *e.P
	if p.Role == "" {
		p.Role = auth.RoleMember
	}
	u := "/api/v1" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req := httptest.NewRequestWithContext(auth.WithInternal(ctx, &p), method, u, nil)
	rec := httptest.NewRecorder()
	e.API.ServeHTTP(rec, req)
	body := bytes.TrimSpace(rec.Body.Bytes())
	if rec.Code >= 300 {
		var j struct{ Error string }
		_ = json.Unmarshal(body, &j)
		if j.Error == "" {
			j.Error = http.StatusText(rec.Code)
		}
		return nil, fmt.Errorf("%s (HTTP %d)", j.Error, rec.Code)
	}
	return body, nil
}

var Tools = []Tool{
	get("workspace_overview", "Looking at the workspace overview", "Security posture of the whole workspace: counts of projects, components, vulnerabilities by risk, malware, policy violations, overdue fixes and recent trends. Start here for broad questions.",
		"/dashboard", map[string]any{"range": str("Trend window: 7d, 30d or 90d")}),
	get("list_projects", "Listing projects", "Projects (repositories, CLI uploads, containers) with their latest scan numbers.",
		"/projects", map[string]any{"name": str("Filter by name (substring)"), "source": str("github, cli or container"), "page": pageParam}),
	get("get_project", "Opening the project", "One project: its branches/versions with IDs, last scan and settings. Use version IDs with attack_path.",
		"/projects/{project_id}", map[string]any{"project_id": str("Project ID")}, "project_id"),
	get("fix_queue", "Checking the fix queue", "What to fix first: packages in priority order with the safe version (fixed_in), upgrade command, deadline (due_at, overdue) and affected projects. share is CUMULATIVE: the % of all open risk removed by fixing this item and every item above it (so item 2 share 88 means items 1+2 together remove 88%). Items have no component ID; link /fix-queue.",
		"/fix-queue", map[string]any{"project_id": str("Limit to one project")}),
	get("search_vulnerabilities", "Searching vulnerabilities", "Vulnerabilities (and malware advisories) found in the workspace with risk, affected projects/components, first seen and deadline.",
		"/vulnerabilities", map[string]any{"id": str("Advisory ID filter (substring), e.g. GHSA- or CVE-2021-44228"), "risk": str("CRITICAL, HIGH, MEDIUM or LOW"), "overdue": str("1 = only past their fix deadline"), "page": pageParam}),
	get("get_vulnerability", "Reading the advisory", "One advisory: summary, aliases (CVE), EPSS, KEV (known exploited), references and fixed versions.",
		"/vulnerabilities/{id}", map[string]any{"id": str("Advisory ID, e.g. GHSA-xxxx or CVE-...")}, "id"),
	get("vulnerability_components", "Finding affected components", "Which components and projects in the workspace an advisory affects.",
		"/vulnerabilities/{id}/components", map[string]any{"id": str("Advisory ID"), "page": pageParam}, "id"),
	get("list_pull_requests", "Checking pull requests", "Pull requests in the team inbox, ranked by urgency (critical, high, medium, low, clean, pending), with the reasons.",
		"/pull-requests", map[string]any{"state": str("open (default), closed, merged or all"), "level": str("Urgency level filter"), "q": str("Search title, repository or number"), "project_id": str("Project ID"), "page": pageParam}),
	get("get_pull_request", "Opening the pull request", "One pull request: urgency reasons, the depguard check result, packages it adds or changes, review findings and history.",
		"/projects/{project_id}/pull-requests/{number}", map[string]any{"project_id": str("Project ID"), "number": num("Pull request number")}, "project_id", "number"),
	get("list_violations", "Checking policy violations", "Current policy violations (what breaks the team policy, blocking or not) across projects.",
		"/policy/violations", map[string]any{"project_id": str("Project ID"), "category": str("Rule category"), "rule": str("Rule name"), "page": pageParam}),
	get("get_policy", "Reading the policy", "The team's security policy: enabled presets and custom rules (what blocks a PR or an install).",
		"/policy", nil),
	get("search_components", "Searching packages", "Find packages (components) used anywhere in the workspace by name, version or ecosystem; returns component IDs for get_package.",
		"/components", map[string]any{"name": str("Package name (substring)"), "version": str("Exact version"), "ecosystem": str("npm, PyPI, Go, Maven, ..."), "page": pageParam}),
	get("get_package", "Opening the package", "One component: health score with its factors, vulnerabilities, malware verdict, license and which projects use it.",
		"/components/{component_id}", map[string]any{"component_id": str("Component ID from search_components")}, "component_id"),
	get("attack_path", "Tracing the dependency path", "How packages reach a project version: dependency chains from the project's manifests down to a vulnerable or flagged package.",
		"/projects/{project_id}/versions/{version_id}/paths", map[string]any{"project_id": str("Project ID"), "version_id": str("Version ID from get_project"), "advisory": str("Advisory ID to trace"), "target": str("Component ID to trace")}, "project_id", "version_id"),
	get("list_fix_prs", "Checking fix pull requests", "Upgrade pull requests depguard opened (auto-fix): status, versions, links.",
		"/fixes", map[string]any{"project_id": str("Project ID"), "status": str("queued, open, merged, closed, failed or unsupported"), "page": pageParam}),
	get("list_endpoints", "Checking machines", "Developer machines and CI runners reporting to depguard, with their last sync.",
		"/endpoints", map[string]any{"hostname": str("Hostname (substring)"), "page": pageParam}),
	get("list_scans", "Checking scans", "Recent scans with their status and counts.",
		"/scans", map[string]any{"page": pageParam}),
	get("secrets_overview", "Checking the secrets vault", "Each project's end-to-end encrypted vault: number of files, members, whether you have access, and secrets that leaked in pull requests. Never contains secret values.",
		"/vaults", nil),
	{Name: "audit_log", Label: "Reading the audit log", Admin: true, Description: "Who changed what in depguard (settings, policy, keys, vault access, fixes). Owner/admin only.",
		Params: map[string]any{"actor": str("Actor email (substring)"), "action": str("Action (substring), e.g. PUT /policy"), "page": pageParam},
		Run: func(ctx context.Context, e Env, args map[string]any) (any, error) {
			return get("", "", "", "/audit-log", map[string]any{"actor": nil, "action": nil, "page": nil}).Run(ctx, e, args)
		}},
	{Name: "check_packages", Label: "Checking packages against the policy", NoMCP: true,
		Description: "Would these packages be allowed to install? Runs the team policy (malware, vulnerabilities, typosquats, licenses, release age) on packages that may not be in the workspace yet.",
		Params: map[string]any{"packages": map[string]any{"type": "array", "items": map[string]any{"type": "object", "required": []string{"ecosystem", "name"},
			"properties": map[string]any{"ecosystem": str("npm, PyPI, Go, Maven, Cargo, ..."), "name": str("Package name"), "version": str("Version; omit for latest")}}}},
		Required: []string{"packages"},
		Run: func(ctx context.Context, e Env, args map[string]any) (any, error) {
			if e.Check == nil {
				return nil, errors.New("package checks are not available")
			}
			b, _ := json.Marshal(args)
			var req engine.CheckRequest
			if err := json.Unmarshal(b, &req); err != nil {
				return nil, err
			}
			return e.Check(ctx, e.P.TenantID, req)
		}},
	{Name: "describe_data", Label: "Looking up the data model",
		Description: "Tables (views) and columns available to run_sql. Call before writing SQL.",
		Run: func(ctx context.Context, e Env, _ map[string]any) (any, error) {
			if e.SQL == nil {
				return nil, errors.New("SQL is not available")
			}
			return e.SQL.Schema(ctx)
		}},
	{Name: "run_sql", Label: "Querying the data",
		Description: "Read-only PostgreSQL SELECT over the q_* views (see describe_data) for questions the other tools can't answer, e.g. joins across projects, packages and pull requests. One statement, at most 1000 rows, 10 s.",
		Params:      map[string]any{"sql": str("A single SELECT or WITH statement")}, Required: []string{"sql"},
		Run: func(ctx context.Context, e Env, args map[string]any) (any, error) {
			if e.SQL == nil {
				return nil, errors.New("SQL is not available")
			}
			s, _ := args["sql"].(string)
			return e.SQL.Run(ctx, e.P.TenantID, s)
		}},
}

// secretKeys never leave a tool: hashes of secret values and key material.
var secretKeys = map[string]bool{"fingerprint": true, "fingerprints": true, "ciphertext": true, "iv": true, "wrapped": true,
	"wrapped_private": true, "public_key": true, "sha256": true, "vault_matches": true, "key_hash": true}

// MaxResult bounds what one tool result adds to the conversation.
const MaxResult = 24 << 10

// Run runs a tool and returns JSON safe to show the model.
func Run(ctx context.Context, e Env, t Tool, args map[string]any) json.RawMessage {
	v, err := t.Run(ctx, e, args)
	if err != nil {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		return b
	}
	raw, ok := v.(json.RawMessage)
	if !ok {
		raw, _ = json.Marshal(v)
	}
	var anyv any
	if json.Unmarshal(raw, &anyv) == nil {
		raw, _ = json.Marshal(redact(anyv))
		// Too big: keep the first (most important) list items as valid JSON.
		if m, ok := anyv.(map[string]any); ok {
			if items, ok := m["items"].([]any); ok {
				for len(raw) > MaxResult && len(items) > 1 {
					items = items[:len(items)/2]
					m["items"], m["items_shown"] = items, len(items)
					m["note"] = "Only the first items are shown; ask about a project, package or page for more."
					raw, _ = json.Marshal(m)
				}
			}
		}
	}
	if len(raw) > MaxResult {
		b, _ := json.Marshal(map[string]any{"truncated": true, "note": "Result too large; narrow the question (filters, page, LIMIT).",
			"partial": string(raw[:MaxResult])})
		return b
	}
	return raw
}

func redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretKeys[k] {
				delete(x, k)
				continue
			}
			x[k] = redact(val)
		}
	case []any:
		for i := range x {
			x[i] = redact(x[i])
		}
	}
	return v
}
