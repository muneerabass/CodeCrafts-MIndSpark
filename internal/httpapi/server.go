// Package httpapi is the REST API: /api/v1/* for the web app (service JWT),
// /v1/* machine endpoints (API key), plus mounts for /mcp, /github/webhook and
// the River UI.
package httpapi

import (
	"context"
	"github.com/depguard/depguard/internal/engine"
	"log/slog"
	"net/http"

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/query"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

// Deps are the server's collaborators. Optional fields may be nil; the
// corresponding endpoints then answer 503.
type Deps struct {
	Pool         *pgxpool.Pool         // depguard_app (RLS)
	Jobs         *river.Client[pgx.Tx] // insert-only River client
	JobOpts      *river.InsertOpts     // scan job options (ghapp.JobOpts); nil means MaxAttempts 5
	Query        *query.Executor       // depguard_query pool
	JWTSecret    []byte
	PublicURL    string // web base URL, for scan links
	PublicAPIURL string // machine API base URL, surfaced in /integrations for setup guides
	Logger       *slog.Logger

	// API-key rate limit (requests/second sustained, burst). Zero means 10/50.
	APIKeyRPS   float64
	APIKeyBurst int

	GitHubInstallURL func() string                                      // ghapp.InstallURL
	Redeliver        func(ctx context.Context, deliveryID string) error // ghapp.Redeliver
	FeedsStatus      func(ctx context.Context) (any, error)             // feeds.Status
	Webhook          http.Handler                                       // POST /github/webhook
	MCP              http.Handler                                       // /mcp (API-key auth applied here)
	// CheckPackages is the pre-install verdict (engine.Deps.CheckPackages); nil answers 503.
	CheckPackages func(ctx context.Context, tenant string, req engine.CheckRequest) (*engine.CheckResult, error)
	RiverUI       http.Handler // /admin/river/ (sa JWT applied here)
}

// Server holds dependencies for handlers.
type Server struct {
	d   Deps
	log *slog.Logger
}

const (
	jsonLimit   = 1 << 20  // 1 MiB for ordinary JSON bodies
	ingestLimit = 10 << 20 // 10 MiB for endpoint ingest
)

// New builds the HTTP handler for all API routes.
func New(d Deps) http.Handler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.JobOpts == nil {
		d.JobOpts = &river.InsertOpts{MaxAttempts: 5}
	}
	if d.APIKeyRPS == 0 {
		d.APIKeyRPS, d.APIKeyBurst = 10, 50
	}
	s := &Server{d: d, log: d.Logger}
	mux := http.NewServeMux()

	jwt := func(h http.Handler) http.Handler { return auth.JWTMiddleware(d.JWTSecret, h) }
	read := func(h handler) http.Handler { return jwt(auth.RequireTenant(s.activeTenant(s.serve(h)))) }
	write := func(h handler) http.Handler {
		return jwt(auth.RequireTenant(s.activeTenant(auth.RequireWrite(s.serve(h)))))
	}
	admin := func(h handler) http.Handler { return jwt(auth.RequireSA(s.serve(h))) }
	key := func(h http.Handler) http.Handler {
		return auth.APIKeyMiddleware(d.Pool, d.APIKeyRPS, d.APIKeyBurst, h)
	}

	// Web (service JWT).
	mux.Handle("GET /api/v1/dashboard", read(s.dashboard))
	mux.Handle("GET /api/v1/projects", read(s.listProjects))
	mux.Handle("GET /api/v1/projects/{id}", read(s.getProject))
	mux.Handle("GET /api/v1/projects/{id}/versions/{vid}/summary", read(s.versionSummary))
	mux.Handle("GET /api/v1/projects/{id}/versions/{vid}/components", read(s.versionComponents))
	mux.Handle("GET /api/v1/projects/{id}/versions/{vid}/vulnerabilities", read(s.versionVulns))
	mux.Handle("GET /api/v1/projects/{id}/versions/{vid}/violations", read(s.versionViolations))
	mux.Handle("GET /api/v1/projects/{id}/versions/{vid}/scans", read(s.versionScans))
	mux.Handle("GET /api/v1/projects/{id}/versions/{vid}/paths", read(s.versionPaths))
	mux.Handle("GET /api/v1/projects/{id}/versions/{vid}/licenses", read(s.versionLicenses))
	mux.Handle("GET /api/v1/projects/{id}/settings", read(s.getProjectSettings))
	mux.Handle("PUT /api/v1/projects/{id}/settings", write(s.putProjectSettings))
	mux.Handle("GET /api/v1/repositories", read(s.listRepositories))
	mux.Handle("POST /api/v1/scans", write(s.createScan))
	mux.Handle("GET /api/v1/components", read(s.listComponents))
	mux.Handle("GET /api/v1/scans", read(s.listScans))
	mux.Handle("GET /api/v1/scans/{id}", read(s.getScan))
	mux.Handle("GET /api/v1/scans/{id}/paths", read(s.scanPaths))
	mux.Handle("GET /api/v1/scans/{id}/report", read(s.scanReport))
	mux.Handle("GET /api/v1/package-analyses", read(s.listAnalyses))
	mux.Handle("GET /api/v1/package-analyses/{id}", read(s.getAnalysis))
	mux.Handle("POST /api/v1/package-analyses/{id}/verify", write(s.verifyAnalysis))
	mux.Handle("GET /api/v1/vulnerabilities", read(s.listVulns))
	mux.Handle("GET /api/v1/vulnerabilities/{id}", read(s.getVuln))
	mux.Handle("GET /api/v1/vulnerabilities/{id}/components", read(s.vulnComponents))
	mux.Handle("GET /api/v1/vulnerabilities/{id}/paths", read(s.vulnPaths))
	mux.Handle("GET /api/v1/policy/violations", read(s.listViolations))
	mux.Handle("GET /api/v1/policy", read(s.getPolicy))
	mux.Handle("PUT /api/v1/policy", write(s.putPolicy))
	mux.Handle("POST /api/v1/policy/test", read(s.testPolicy))
	mux.Handle("GET /api/v1/pull-requests", read(s.listPullRequests))
	mux.Handle("GET /api/v1/pull-requests/summary", read(s.prSummary))
	mux.Handle("GET /api/v1/projects/{id}/pull-requests", read(s.projectPullRequests))
	mux.Handle("GET /api/v1/projects/{id}/pull-requests/{number}", read(s.getPullRequest))
	mux.Handle("POST /api/v1/projects/{id}/pull-requests/{number}/{action}", write(s.prAction))
	mux.Handle("GET /api/v1/settings/pr", read(s.getPRSettings))
	mux.Handle("PUT /api/v1/settings/pr", write(s.putPRSettings))
	mux.Handle("GET /api/v1/fixes", read(s.listFixes))
	mux.Handle("GET /api/v1/fix-queue", read(s.fixQueue))
	mux.Handle("GET /api/v1/settings/notifications", read(s.getNotifications))
	mux.Handle("PUT /api/v1/settings/notifications", write(s.putNotifications))
	mux.Handle("POST /api/v1/settings/notifications/test", write(s.testNotification))
	mux.Handle("GET /api/v1/jira/links", read(s.listJiraLinks))
	mux.Handle("POST /api/v1/jira/issues", write(s.createJiraIssue))
	mux.Handle("GET /api/v1/settings/sla", read(s.getSLA))
	mux.Handle("PUT /api/v1/settings/sla", write(s.putSLA))
	mux.Handle("POST /api/v1/projects/{id}/fixes", write(s.createFix))
	mux.Handle("GET /api/v1/settings/fixes", read(s.getFixSettings))
	mux.Handle("PUT /api/v1/settings/fixes", write(s.putFixSettings))
	mux.Handle("GET /api/v1/endpoints", read(s.listEndpoints))
	mux.Handle("GET /api/v1/endpoints/{id}", read(s.getEndpoint))
	mux.Handle("GET /api/v1/endpoints/{id}/inventory", read(s.endpointInventory))
	mux.Handle("GET /api/v1/endpoints/{id}/package-events", read(s.endpointPackageEvents))
	mux.Handle("GET /api/v1/endpoints/{id}/agent-events", read(s.endpointAgentEvents))
	mux.Handle("POST /api/v1/query", read(s.runQuery))
	mux.Handle("GET /api/v1/query/schema", read(s.querySchema))
	mux.Handle("GET /api/v1/queries", read(s.listQueries))
	mux.Handle("POST /api/v1/queries", read(s.createQuery))
	mux.Handle("DELETE /api/v1/queries/{id}", read(s.deleteQuery))
	mux.Handle("GET /api/v1/settings", read(s.getSettings))
	mux.Handle("PUT /api/v1/settings", write(s.putSettings))
	mux.Handle("GET /api/v1/api-keys", read(s.listKeys))
	mux.Handle("POST /api/v1/api-keys", write(s.createKey))
	mux.Handle("DELETE /api/v1/api-keys/{id}", write(s.revokeKey))
	mux.Handle("GET /api/v1/exclusions", read(s.listExclusions))
	mux.Handle("POST /api/v1/exclusions", write(s.createExclusion))
	mux.Handle("PUT /api/v1/exclusions/{id}", write(s.updateExclusion))
	mux.Handle("DELETE /api/v1/exclusions/{id}", write(s.deleteExclusion))
	mux.Handle("GET /api/v1/integrations", read(s.integrations))

	// Super-admin.
	mux.Handle("POST /api/v1/admin/tenants", admin(s.adminCreateTenant))
	mux.Handle("GET /api/v1/admin/tenants", admin(s.adminListTenants))
	mux.Handle("PATCH /api/v1/admin/tenants/{id}", admin(s.adminPatchTenant))
	mux.Handle("GET /api/v1/admin/installations", admin(s.adminListInstallations))
	mux.Handle("POST /api/v1/admin/installations/{id}/link", admin(s.adminLinkInstallation))
	mux.Handle("POST /api/v1/admin/installations/{id}/unlink", admin(s.adminUnlinkInstallation))
	mux.Handle("GET /api/v1/admin/feeds", admin(s.adminFeeds))
	mux.Handle("GET /api/v1/admin/webhooks", admin(s.adminWebhooks))
	mux.Handle("POST /api/v1/admin/webhooks/{delivery_id}/redeliver", admin(s.adminRedeliver))
	mux.Handle("GET /api/v1/admin/jobs/failed", admin(s.adminFailedJobs))
	if d.RiverUI != nil {
		mux.Handle("/admin/river/", jwt(auth.RequireSA(d.RiverUI)))
	}

	// Machine (API key).
	mux.Handle("POST /v1/scans", key(s.serve(s.uploadScan)))
	mux.Handle("GET /v1/scans/{id}", key(s.serve(s.machineGetScan)))
	mux.Handle("GET /v1/scans/{id}/report", key(s.serve(s.scanReport)))
	mux.Handle("POST /v1/packages/check", key(s.serve(s.checkPackages)))
	mux.Handle("GET /v1/me", key(s.serve(s.me)))
	mux.Handle("POST /v1/endpoints/checkin", key(s.serve(s.checkin)))
	mux.Handle("POST /v1/endpoints/{id}/inventory", key(s.serve(s.ingestInventory)))
	mux.Handle("POST /v1/endpoints/{id}/pmg-events", key(s.serve(s.ingestPMG)))
	mux.Handle("POST /v1/endpoints/{id}/agent-events", key(s.serve(s.ingestAgentEvents)))
	if d.MCP != nil {
		mux.Handle("/mcp", key(d.MCP))
	}
	if d.Webhook != nil {
		mux.Handle("POST /github/webhook", http.MaxBytesHandler(d.Webhook, 25<<20))
	}

	// Unknown /api and /v1 paths get JSON 404s.
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.JSONError(w, http.StatusNotFound, "not found")
	}))
	return mux
}

func unavailable(what string) error {
	return errf(http.StatusServiceUnavailable, "%s not configured", what)
}

// activeTenant rejects service-JWT requests for a disabled tenant (API keys are
// already rejected at lookup). Platform super-admins keep read access for support.
func (s *Server) activeTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := auth.FromContext(r.Context())
		var disabled bool
		err := db.WithTenantTx(r.Context(), s.d.Pool, p.TenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(r.Context(),
				`SELECT EXISTS (SELECT 1 FROM tenant_settings WHERE disabled_at IS NOT NULL)`).Scan(&disabled)
		})
		if err != nil {
			s.log.Error("tenant status check", "err", err)
			auth.JSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if disabled && !(p.SA && r.Method == http.MethodGet) {
			auth.JSONError(w, http.StatusForbidden, "tenant disabled")
			return
		}
		next.ServeHTTP(w, r)
	})
}
