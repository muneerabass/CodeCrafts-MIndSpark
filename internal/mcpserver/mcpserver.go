// Package mcpserver exposes depguard's package intelligence as MCP tools over
// streamable HTTP. Authentication (API key → tenant principal) is applied by
// the caller; tools read the principal from the request context.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/assist"
	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/engine"
	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/query"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/safedep/vet/pkg/models"
)

// Version is reported to MCP clients.
const Version = "0.1.0"

// CheckFunc is the tenant's pre-install policy check (engine.Deps.CheckPackages).
type CheckFunc func(ctx context.Context, tenant string, req engine.CheckRequest) (*engine.CheckResult, error)

type tools struct {
	pool  *pgxpool.Pool
	enr   *enrich.Enricher
	check CheckFunc
}

// Instructions are sent to every MCP client: the rules an agent follows.
const Instructions = `depguard checks open source packages against your team's security policy: malware, known vulnerabilities, typosquats, licenses and package health.

Before you install, add or upgrade ANY dependency (npm/pnpm/yarn/bun, pip/uv/poetry, go get, cargo, gem, composer, maven, nuget) - including ones you are about to write into a manifest - call check_packages with every package you plan to add, in one call.
- decision "block": do NOT install it. Tell the user it was blocked and why, and offer the suggested safer version or an alternative.
- decision "warn": you may install it, but tell the user the warning in one line.
- decision "allow": install it; no need to mention depguard.
Never work around a block (other registries, vendoring, copying the code). Only the user can override it, from depguard.

For questions about this team's workspace - what to fix first, why a pull request is blocked, where a package or vulnerability is used, policy, deadlines, leaked vault secrets - use the "Workspace:" tools (workspace_overview, fix_queue, search_components, list_pull_requests, run_sql, ...) instead of guessing. They are read-only; tell the user which depguard page to use for changes.`

// NewServer builds the MCP server with depguard's tools; check may be nil (no check_packages).
// Workspace gives MCP clients the assistant's read-only workspace tools.
type Workspace struct {
	API http.Handler    // the REST API, read in-process as a member
	SQL *query.Executor // depguard_ai
}

func NewServer(pool *pgxpool.Pool, enr *enrich.Enricher, check CheckFunc, ws *Workspace) *server.MCPServer {
	t := &tools{pool: pool, enr: enr, check: check}
	s := server.NewMCPServer("depguard", Version, server.WithToolCapabilities(false), server.WithRecovery(), server.WithInstructions(Instructions))
	if check != nil {
		s.AddTool(mcp.NewTool("check_packages",
			mcp.WithDescription("Check packages against the team's depguard policy BEFORE installing or adding them. Returns allow, warn or block per package with the reasons and a safer version when one exists. Omit version to check the latest release."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithArray("packages", mcp.Required(), mcp.Description("Packages to check (max 100)"), mcp.Items(map[string]any{
				"type": "object", "required": []string{"ecosystem", "name"},
				"properties": map[string]any{
					"ecosystem": map[string]any{"type": "string", "description": "npm, PyPI, Go, Maven, Cargo, RubyGems, Packagist or NuGet"},
					"name":      map[string]any{"type": "string", "description": "Package name, e.g. lodash, requests, github.com/gin-gonic/gin"},
					"version":   map[string]any{"type": "string", "description": "Exact version; omit for the latest release"},
				},
			}))), t.checkPackages)
	}
	pkgArgs := []mcp.ToolOption{
		mcp.WithString("ecosystem", mcp.Required(), mcp.Description("Package ecosystem: npm, PyPI, Go, Maven, Cargo, RubyGems, Packagist, NuGet, Hex, Pub, GitHubActions")),
		mcp.WithString("name", mcp.Required(), mcp.Description("Package name, e.g. lodash or org.apache.logging.log4j:log4j-core")),
		mcp.WithString("version", mcp.Required(), mcp.Description("Exact package version")),
	}
	tool := func(name, desc string) mcp.Tool {
		return mcp.NewTool(name, append([]mcp.ToolOption{mcp.WithDescription(desc), mcp.WithReadOnlyHintAnnotation(true)}, pkgArgs...)...)
	}
	s.AddTool(tool("get_package_vulnerabilities", "List known vulnerabilities (OSV) affecting a package version."), t.vulnerabilities)
	s.AddTool(tool("get_malware_verdict", "Malware verdict for a package version from OSV malicious-package advisories and this tenant's package analyses."), t.malware)
	s.AddTool(tool("get_license_info", "SPDX licenses declared by a package version."), t.licenses)
	s.AddTool(tool("get_package_scorecard", "OpenSSF Scorecard and repository popularity for a package's source repository."), t.scorecard)
	if ws != nil {
		addWorkspace(s, ws)
	}
	return s
}

// Handler serves MCP over streamable HTTP (stateless; each request carries its API key).
func Handler(pool *pgxpool.Pool, enr *enrich.Enricher, check CheckFunc, ws *Workspace) http.Handler {
	return http.MaxBytesHandler(server.NewStreamableHTTPServer(NewServer(pool, enr, check, ws), server.WithStateLess(true)), 1<<20)
}

// addWorkspace registers the assistant tools an API key (member level) may use.
func addWorkspace(s *server.MCPServer, ws *Workspace) {
	for _, at := range assist.For(assist.Env{P: &auth.Principal{Role: auth.RoleMember}}, true) {
		schema, _ := json.Marshal(at.Spec().Schema)
		tool := mcp.NewToolWithRawSchema(at.Name, "Workspace: "+at.Description, schema)
		tool.Annotations.ReadOnlyHint = mcp.ToBoolPtr(true)
		s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			p := auth.FromContext(ctx)
			if p == nil || p.TenantID == "" {
				return mcp.NewToolResultError("unauthorized"), nil
			}
			e := assist.Env{P: &auth.Principal{TenantID: p.TenantID, APIKeyID: p.APIKeyID, Role: auth.RoleMember}, API: ws.API, SQL: ws.SQL}
			out := assist.Run(ctx, e, at, req.GetArguments())
			if strings.HasPrefix(string(out), `{"error"`) {
				return mcp.NewToolResultError(string(out)), nil
			}
			return mcp.NewToolResultText(string(out)), nil
		})
	}
}

var ecosystems = map[string]string{
	"npm": models.EcosystemNpm, "pypi": models.EcosystemPyPI, "go": models.EcosystemGo, "golang": models.EcosystemGo,
	"maven": models.EcosystemMaven, "cargo": models.EcosystemCargo, "crates.io": models.EcosystemCargo,
	"rubygems": models.EcosystemRubyGems, "packagist": models.EcosystemPackagist, "nuget": models.EcosystemNuGet,
	"hex": models.EcosystemHex, "pub": models.EcosystemPub, "githubactions": models.EcosystemGitHubActions,
	"github actions": models.EcosystemGitHubActions,
}

type pkgRef struct{ Ecosystem, Name, Version string }

// lookup validates arguments and enriches the package from the local mirror.
func (t *tools) lookup(ctx context.Context, req mcp.CallToolRequest) (*pkgRef, *models.Package, error) {
	eco, err1 := req.RequireString("ecosystem")
	name, err2 := req.RequireString("name")
	version, err3 := req.RequireString("version")
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, nil, err
	}
	vetEco, ok := ecosystems[strings.ToLower(strings.TrimSpace(eco))]
	if !ok {
		return nil, nil, errors.New("unsupported ecosystem " + eco)
	}
	ref := &pkgRef{vetEco, strings.TrimSpace(name), strings.TrimSpace(version)}
	pkg := &models.Package{Manifest: models.NewPackageManifestFromLocal("mcp", vetEco)}
	pkg.Name, pkg.Version = ref.Name, ref.Version
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := t.enr.Enrich(ctx, []*models.Package{pkg}); err != nil {
		return nil, nil, err
	}
	return ref, pkg, nil
}

func result(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultStructured(v, string(b)), nil
}

func (t *tools) vulnerabilities(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ref, pkg, err := t.lookup(ctx, req)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	vulns := []map[string]any{}
	for _, m := range enrich.Matches(pkg) {
		if m.Malware {
			continue
		}
		vulns = append(vulns, map[string]any{"id": m.AdvisoryID, "summary": m.Summary, "risk": m.Risk, "aliases": m.Aliases})
	}
	return result(map[string]any{"package": ref, "vulnerabilities": vulns, "count": len(vulns)})
}

func (t *tools) malware(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ref, pkg, err := t.lookup(ctx, req)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	advisories := []string{}
	for _, m := range enrich.Matches(pkg) {
		if m.Malware {
			advisories = append(advisories, m.AdvisoryID)
		}
	}
	var analysis map[string]any
	if p := auth.FromContext(ctx); p != nil && p.TenantID != "" {
		err := db.WithTenantTx(ctx, t.pool, p.TenantID, func(tx pgx.Tx) error {
			var status, source string
			var verified bool
			var at time.Time
			err := tx.QueryRow(ctx, `SELECT a.status, a.verified, a.source, a.created_at FROM package_analyses a
				JOIN components c ON c.id = a.component_id
				WHERE c.ecosystem = $1 AND c.name = $2 AND c.version = $3 ORDER BY a.created_at DESC LIMIT 1`,
				ref.Ecosystem, ref.Name, ref.Version).Scan(&status, &verified, &source, &at)
			if err == nil {
				analysis = map[string]any{"status": status, "verified": verified, "source": source, "analyzed_at": at}
			}
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	verdict := "no_known_malware"
	switch {
	case len(advisories) > 0 || (analysis != nil && analysis["status"] == "malicious"):
		verdict = "malicious"
	case analysis != nil && analysis["status"] == "suspicious":
		verdict = "suspicious"
	case analysis != nil && analysis["verified"] == true:
		verdict = "clean"
	}
	return result(map[string]any{"package": ref, "verdict": verdict, "malware_advisories": advisories, "analysis": analysis})
}

func (t *tools) licenses(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ref, pkg, err := t.lookup(ctx, req)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	lic := []string{}
	if pkg.Insights != nil && pkg.Insights.Licenses != nil {
		for _, l := range *pkg.Insights.Licenses {
			lic = append(lic, string(l))
		}
	}
	return result(map[string]any{"package": ref, "licenses": lic, "source": "deps.dev"})
}

func (t *tools) scorecard(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ref, pkg, err := t.lookup(ctx, req)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	out := map[string]any{"package": ref, "repository": nil, "scorecard": nil}
	if ins := pkg.Insights; ins != nil {
		if ins.Projects != nil && len(*ins.Projects) > 0 {
			p := (*ins.Projects)[0]
			out["repository"] = map[string]any{"name": p.Name, "stars": p.Stars, "forks": p.Forks}
		}
		if ins.Scorecard != nil && ins.Scorecard.Content != nil {
			out["scorecard"] = ins.Scorecard.Content
		}
	}
	return result(out)
}

type checkArgs struct {
	Packages []struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Version   string `json:"version"`
	} `json:"packages"`
}

// checkPackages runs the tenant policy on the packages an agent wants to add.
func (t *tools) checkPackages(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	p := auth.FromContext(ctx)
	if p == nil || p.TenantID == "" {
		return mcp.NewToolResultError("missing depguard API key"), nil
	}
	var a checkArgs
	if err := req.BindArguments(&a); err != nil || len(a.Packages) == 0 || len(a.Packages) > 100 {
		return mcp.NewToolResultError("packages must be a list of 1 to 100 {ecosystem, name, version?} objects"), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var pkgs []engine.CheckPackage
	var notes []string
	for _, x := range a.Packages {
		vetEco, ok := ecosystems[strings.ToLower(strings.TrimSpace(x.Ecosystem))]
		osv := enrich.OSVEcosystemName(vetEco)
		if !ok || osv == "" {
			notes = append(notes, "unsupported ecosystem "+x.Ecosystem+" for "+x.Name)
			continue
		}
		v := strings.TrimSpace(x.Version)
		if v == "" || v == "latest" {
			l, err := t.enr.PackageLatest(ctx, osv, x.Name)
			if err != nil || l == nil || !l.Found || l.DefaultVersion == "" {
				notes = append(notes, x.Name+": package not found in the "+osv+" registry - it may not exist (a typo or hallucinated name). Do not install it.")
				continue
			}
			v = l.DefaultVersion
		}
		pkgs = append(pkgs, engine.CheckPackage{Ecosystem: osv, Name: strings.TrimSpace(x.Name), Version: v})
	}
	out := map[string]any{"decision": engine.DecisionAllow, "packages": []any{}, "notes": notes}
	if len(notes) > 0 {
		out["decision"] = engine.DecisionBlock
	}
	if len(pkgs) == 0 {
		out["agent_instruction"] = strings.Join(notes, " ")
		return result(out)
	}
	res, err := t.check(ctx, p.TenantID, engine.CheckRequest{Packages: pkgs})
	if err != nil {
		return mcp.NewToolResultError("depguard check failed: " + err.Error()), nil
	}
	verdicts := map[string]engine.CheckVerdict{}
	for _, v := range res.Packages {
		verdicts[v.Ecosystem+"/"+v.Name+"@"+v.Version] = v
	}
	// For blocked or warned packages, see whether the latest release is clean.
	var alts []engine.CheckPackage
	for _, c := range pkgs {
		if v, ok := verdicts[c.Ecosystem+"/"+c.Name+"@"+c.Version]; ok && v.Decision != engine.DecisionAllow {
			if l, _ := t.enr.PackageLatest(ctx, c.Ecosystem, c.Name); l != nil && l.DefaultVersion != "" && l.DefaultVersion != c.Version {
				alts = append(alts, engine.CheckPackage{Ecosystem: c.Ecosystem, Name: c.Name, Version: l.DefaultVersion})
			}
		}
	}
	safer := map[string]string{}
	if len(alts) > 0 {
		if ar, err := t.check(ctx, p.TenantID, engine.CheckRequest{Packages: alts}); err == nil {
			bad := map[string]bool{}
			for _, v := range ar.Packages {
				if v.Decision == engine.DecisionBlock {
					bad[v.Ecosystem+"/"+v.Name] = true
				}
			}
			for _, c := range alts {
				if !bad[c.Ecosystem+"/"+c.Name] {
					safer[c.Ecosystem+"/"+c.Name] = c.Version
				}
			}
		}
	}
	var list []any
	var lines []string
	decision := engine.DecisionAllow
	if len(notes) > 0 {
		decision = engine.DecisionBlock
		lines = append(lines, notes...)
	}
	for _, c := range pkgs {
		v, ok := verdicts[c.Ecosystem+"/"+c.Name+"@"+c.Version]
		item := map[string]any{"ecosystem": c.Ecosystem, "name": c.Name, "version": c.Version, "decision": engine.DecisionAllow, "findings": []any{}}
		if ok {
			item["decision"], item["findings"] = v.Decision, v.Findings
			if alt := safer[c.Ecosystem+"/"+c.Name]; alt != "" {
				item["safer_version"] = alt
			}
			var why []string
			for _, f := range v.Findings {
				why = append(why, f.Summary)
			}
			label := c.Name + "@" + c.Version
			reason := strings.TrimRight(strings.Join(why, "; "), ". ")
			switch v.Decision {
			case engine.DecisionBlock:
				l := "BLOCKED " + label + ": " + reason + ". Do not install it."
				if alt := safer[c.Ecosystem+"/"+c.Name]; alt != "" {
					l += " Use " + c.Name + "@" + alt + " instead (passes the policy)."
				}
				lines = append(lines, l)
			case engine.DecisionWarn:
				lines = append(lines, "WARNING "+label+": "+reason+". Allowed, but tell the user.")
			}
			if v.Decision == engine.DecisionBlock || (v.Decision == engine.DecisionWarn && decision == engine.DecisionAllow) {
				decision = v.Decision
			}
		}
		list = append(list, item)
	}
	if len(lines) == 0 {
		lines = append(lines, "All packages pass the team policy. Install them.")
	}
	out["decision"], out["packages"], out["agent_instruction"] = decision, list, strings.Join(lines, "\n")
	out["block_mode"] = res.BlockMode
	return result(out)
}
