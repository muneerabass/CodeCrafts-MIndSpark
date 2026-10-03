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

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/enrich"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/safedep/vet/pkg/models"
)

// Version is reported to MCP clients.
const Version = "0.1.0"

type tools struct {
	pool *pgxpool.Pool
	enr  *enrich.Enricher
}

// NewServer builds the MCP server with depguard's tools.
func NewServer(pool *pgxpool.Pool, enr *enrich.Enricher) *server.MCPServer {
	t := &tools{pool: pool, enr: enr}
	s := server.NewMCPServer("depguard", Version, server.WithToolCapabilities(false), server.WithRecovery(),
		server.WithInstructions("Supply-chain intelligence for open source packages: known vulnerabilities, malware verdicts, licenses and OpenSSF Scorecard."))
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
	return s
}

// Handler serves MCP over streamable HTTP (stateless; each request carries its API key).
func Handler(pool *pgxpool.Pool, enr *enrich.Enricher) http.Handler {
	return http.MaxBytesHandler(server.NewStreamableHTTPServer(NewServer(pool, enr), server.WithStateLess(true)), 1<<20)
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
