package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/query"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// --------------------------------------------------------------- settings

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `SELECT jsonb_build_object('tenant_id', tenant_id, 'domain', domain, 'plan', plan,
			'block_mode', block_mode, 'scan_draft_prs', scan_draft_prs, 'suppress_clean_comments', suppress_clean_comments)
			FROM tenant_settings`)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errf(http.StatusNotFound, "tenant not provisioned")
	}
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		BlockMode             *bool `json:"block_mode"`
		ScanDraftPRs          *bool `json:"scan_draft_prs"`
		SuppressCleanComments *bool `json:"suppress_clean_comments"`
		// Read-only fields are accepted (the web may send the whole object) and ignored.
		TenantID string `json:"tenant_id"`
		Domain   string `json:"domain"`
		Plan     string `json:"plan"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE tenant_settings SET
			block_mode = COALESCE($1, block_mode), scan_draft_prs = COALESCE($2, scan_draft_prs),
			suppress_clean_comments = COALESCE($3, suppress_clean_comments), updated_at = now()`,
			body.BlockMode, body.ScanDraftPRs, body.SuppressCleanComments)
		if err == nil && tag.RowsAffected() == 0 {
			return errf(http.StatusNotFound, "tenant not provisioned")
		}
		return err
	})
	if err != nil {
		return err
	}
	return s.getSettings(w, r)
}

// --------------------------------------------------------------- API keys

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) error {
	keys, err := auth.ListKeys(r.Context(), s.d.Pool, principal(r).TenantID)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"items": keys, "total": len(keys)})
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Name      string     `json:"name"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 100 {
		return badRequest("name is required (max 100 chars)")
	}
	if body.ExpiresAt != nil && !body.ExpiresAt.After(time.Now()) {
		return badRequest("expires_at must be in the future")
	}
	p := principal(r)
	k, err := auth.CreateKey(r.Context(), s.d.Pool, p.TenantID, p.UserID, body.Name, body.ExpiresAt)
	if err != nil {
		return err
	}
	auditDetail(r, "name", body.Name)
	return writeJSON(w, http.StatusCreated, k)
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) error {
	err := auth.RevokeKey(r.Context(), s.d.Pool, principal(r).TenantID, r.PathValue("id"))
	if errors.Is(err, auth.ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ------------------------------------------------------------- exclusions

const exclusionInner = `SELECT id, ecosystem, name, version, reason, expires_at, created_at,
  CASE WHEN expires_at IS NOT NULL AND expires_at <= now() THEN 'expired' ELSE 'active' END AS status
FROM exclusions`

func (s *Server) listExclusions(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", exclusionInner,
		filterSpec{eq: map[string]string{"ecosystem": "t.ecosystem", "version": "t.version", "status": "t.status"},
			ilike: map[string]string{"name": "t.name"}, dateCol: "t.created_at"},
		"t.created_at DESC, t.id", func(r *http.Request, w *where) error {
			if v := r.URL.Query().Get("expiry_before"); v != "" {
				t, err := parseTime(v, false)
				if err != nil {
					return badRequest("expiry_before must be RFC3339 or YYYY-MM-DD")
				}
				w.add("t.expires_at < ?", t)
			}
			return nil
		})(w, r)
}

type exclusionBody struct {
	Ecosystem string     `json:"ecosystem"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (b *exclusionBody) validate() error {
	b.Ecosystem, b.Name, b.Version = strings.TrimSpace(b.Ecosystem), strings.TrimSpace(b.Name), strings.TrimSpace(b.Version)
	if b.Version == "" {
		b.Version = "*"
	}
	if b.Ecosystem == "" || b.Name == "" || strings.TrimSpace(b.Reason) == "" {
		return badRequest("ecosystem, name and reason are required")
	}
	if len(b.Name) > 300 || len(b.Reason) > 2000 || len(b.Version) > 200 {
		return badRequest("field too long")
	}
	return nil
}

func (s *Server) writeExclusion(w http.ResponseWriter, r *http.Request, id string) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `SELECT to_jsonb(t) FROM (`+exclusionInner+`) t WHERE t.id = $1`, id)
		return err
	})
	if err != nil {
		return err
	}
	code := http.StatusOK
	if r.Method == http.MethodPost {
		code = http.StatusCreated
	}
	return writeJSON(w, code, out)
}

func (s *Server) createExclusion(w http.ResponseWriter, r *http.Request) error {
	var b exclusionBody
	if err := decode(w, r, jsonLimit, &b); err != nil {
		return err
	}
	if err := b.validate(); err != nil {
		return err
	}
	id := ids.New()
	p := principal(r)
	auditDetail(r, "package", b.Ecosystem+"/"+b.Name+"@"+b.Version)
	auditDetail(r, "reason", b.Reason)
	err := s.tx(r, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO exclusions (id, tenant_id, ecosystem, name, version, reason, expires_at, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, p.TenantID, b.Ecosystem, b.Name, b.Version, b.Reason, b.ExpiresAt, p.UserID)
		return err
	})
	if err != nil {
		return err
	}
	return s.writeExclusion(w, r, id)
}

func (s *Server) updateExclusion(w http.ResponseWriter, r *http.Request) error {
	var b exclusionBody
	if err := decode(w, r, jsonLimit, &b); err != nil {
		return err
	}
	if err := b.validate(); err != nil {
		return err
	}
	id := r.PathValue("id")
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE exclusions SET ecosystem=$2, name=$3, version=$4, reason=$5, expires_at=$6 WHERE id=$1`,
			id, b.Ecosystem, b.Name, b.Version, b.Reason, b.ExpiresAt)
		if err == nil && tag.RowsAffected() == 0 {
			return errNotFound
		}
		return err
	})
	if err != nil {
		return err
	}
	return s.writeExclusion(w, r, id)
}

func (s *Server) deleteExclusion(w http.ResponseWriter, r *http.Request) error {
	return s.deleteByID(w, r, "exclusions")
}

func (s *Server) deleteByID(w http.ResponseWriter, r *http.Request, table string) error {
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `DELETE FROM `+table+` WHERE id = $1`, r.PathValue("id"))
		if err == nil && tag.RowsAffected() == 0 {
			return errNotFound
		}
		return err
	})
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ------------------------------------------------------------------ query

func (s *Server) runQuery(w http.ResponseWriter, r *http.Request) error {
	if s.d.Query == nil {
		return unavailable("query executor")
	}
	var body struct {
		SQL string `json:"sql"`
	}
	if err := decode(w, r, 64<<10, &body); err != nil {
		return err
	}
	res, err := s.d.Query.Run(r.Context(), principal(r).TenantID, body.SQL)
	var pe *pgconn.PgError
	if errors.Is(err, query.ErrInvalid) || errors.As(err, &pe) {
		// Validation and SQL errors (syntax, permission, timeout) go back to the user.
		return badRequest("%v", err)
	}
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, res)
}

func (s *Server) querySchema(w http.ResponseWriter, r *http.Request) error {
	if s.d.Query == nil {
		return unavailable("query executor")
	}
	tables, err := s.d.Query.Schema(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"tables": tables})
}

func (s *Server) listQueries(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `SELECT id, name, sql, created_at FROM saved_queries`,
		filterSpec{ilike: map[string]string{"name": "t.name"}}, "t.created_at DESC, t.id", nil)(w, r)
}

// Saved queries are allowed for every role: they are read-only artifacts.
func (s *Server) createQuery(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Name string `json:"name"`
		SQL  string `json:"sql"`
	}
	if err := decode(w, r, 64<<10, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 200 {
		return badRequest("name is required (max 200 chars)")
	}
	if _, err := query.Validate(body.SQL); err != nil {
		return badRequest("%v", err)
	}
	p := principal(r)
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `INSERT INTO saved_queries (id, tenant_id, name, sql, created_by) VALUES ($1,$2,$3,$4,$5)
			RETURNING jsonb_build_object('id', id, 'name', name, 'sql', sql, 'created_at', created_at)`,
			ids.New(), p.TenantID, body.Name, body.SQL, p.UserID)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, out)
}

func (s *Server) deleteQuery(w http.ResponseWriter, r *http.Request) error {
	return s.deleteByID(w, r, "saved_queries")
}

// ----------------------------------------------------- integrations & repos

func (s *Server) integrations(w http.ResponseWriter, r *http.Request) error {
	installURL := ""
	if s.d.GitHubInstallURL != nil {
		installURL = s.d.GitHubInstallURL()
	}
	type inst struct {
		ID           int64  `json:"id"`
		AccountLogin string `json:"account_login"`
		Status       string `json:"status"`
		Repos        int64  `json:"repos"`
	}
	installs := []inst{}
	err := s.tx(r, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `SELECT i.id, i.account_login, i.status,
			(SELECT count(*) FROM gh_repositories g WHERE g.installation_id = i.id AND g.removed_at IS NULL)
			FROM gh_installations i WHERE i.tenant_id = $1 ORDER BY i.account_login`, principal(r).TenantID)
		if err != nil {
			return err
		}
		installs, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (inst, error) {
			var i inst
			err := row.Scan(&i.ID, &i.AccountLogin, &i.Status, &i.Repos)
			return i, err
		})
		return err
	})
	if err != nil {
		return err
	}
	apiURL := strings.TrimRight(s.d.PublicAPIURL, "/")
	mcpURL := ""
	if apiURL != "" {
		mcpURL = apiURL + "/mcp"
	}
	return writeJSON(w, http.StatusOK, map[string]any{"github": map[string]any{"install_url": installURL, "installations": installs},
		"api_url": apiURL, "mcp_url": mcpURL})
}

// repositories of linked installations; gh_* are global tables, so the
// tenant filter is explicit.
func (s *Server) listRepositories(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `
SELECT g.id, g.full_name, g.default_branch, g.private, g.installation_id, i.tenant_id
FROM gh_repositories g JOIN gh_installations i ON i.id = g.installation_id
WHERE i.status = 'linked' AND g.removed_at IS NULL`,
		filterSpec{ilike: map[string]string{"name": "t.full_name"}}, "t.full_name", func(r *http.Request, w *where) error {
			w.add("t.tenant_id = ?", principal(r).TenantID)
			return nil
		}, "tenant_id")(w, r)
}

// createScan queues a manual full scan of a linked repository.
func (s *Server) createScan(w http.ResponseWriter, r *http.Request) error {
	if s.d.Jobs == nil {
		return unavailable("job queue")
	}
	var body struct {
		RepoID int64  `json:"repo_id"`
		Branch string `json:"branch"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if body.RepoID == 0 {
		return badRequest("repo_id is required")
	}
	p := principal(r)
	scanID := ids.New()
	auditDetail(r, "scan_id", scanID)
	auditDetail(r, "branch", body.Branch)
	err := s.tx(r, func(tx pgx.Tx) error {
		ctx := r.Context()
		var fullName, defBranch string
		var instID int64
		err := tx.QueryRow(ctx, `SELECT g.full_name, g.default_branch, g.installation_id
			FROM gh_repositories g JOIN gh_installations i ON i.id = g.installation_id
			WHERE g.id = $1 AND g.removed_at IS NULL AND i.status = 'linked' AND i.tenant_id = $2`,
			body.RepoID, p.TenantID).Scan(&fullName, &defBranch, &instID)
		if errors.Is(err, pgx.ErrNoRows) {
			return errf(http.StatusNotFound, "repository not found in a linked installation")
		}
		if err != nil {
			return err
		}
		branch := strings.TrimSpace(body.Branch)
		if branch == "" {
			branch = defBranch
		}
		projectID, versionID, err := upsertProjectVersion(ctx, tx, p.TenantID, "github", fullName, "https://github.com/"+fullName, &body.RepoID, branch)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status)
			VALUES ($1,$2,$3,$4,'manual','queued')`, scanID, p.TenantID, projectID, versionID); err != nil {
			return err
		}
		_, err = s.d.Jobs.InsertTx(ctx, tx, jobs.ScanRepository{TenantID: p.TenantID, InstallationID: instID, RepoID: body.RepoID,
			RepoFullName: fullName, Ref: branch, Trigger: "manual", ScanID: scanID}, s.d.JobOpts)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusAccepted, map[string]string{"scan_id": scanID})
}

// upsertProjectVersion returns ids for (source, name) and its version.
func upsertProjectVersion(ctx context.Context, tx pgx.Tx, tenantID, source, name, url string, ghRepoID *int64, version string) (string, string, error) {
	var projectID, versionID string
	err := tx.QueryRow(ctx, `INSERT INTO projects (id, tenant_id, source, name, url, gh_repo_id) VALUES ($1,$2,$3,$4,NULLIF($5,''),$6)
		ON CONFLICT (tenant_id, source, name) DO UPDATE SET updated_at = now(),
		  url = COALESCE(EXCLUDED.url, projects.url), gh_repo_id = COALESCE(EXCLUDED.gh_repo_id, projects.gh_repo_id)
		RETURNING id`, ids.New(), tenantID, source, name, url, ghRepoID).Scan(&projectID)
	if err != nil {
		return "", "", err
	}
	err = tx.QueryRow(ctx, `INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ($1,$2,$3,$4)
		ON CONFLICT (project_id, name) DO UPDATE SET updated_at = now() RETURNING id`,
		ids.New(), tenantID, projectID, version).Scan(&versionID)
	return projectID, versionID, err
}
