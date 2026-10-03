package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/jackc/pgx/v5"
)

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

func (s *Server) adminCreateTenant(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		TenantID string `json:"tenant_id"`
		Domain   string `json:"domain"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	body.Domain = strings.ToLower(strings.TrimSpace(body.Domain))
	if body.TenantID == "" || len(body.TenantID) > 100 || !domainRe.MatchString(body.Domain) || len(body.Domain) > 253 {
		return badRequest("tenant_id and a valid domain are required")
	}
	var out json.RawMessage
	// Idempotent: re-provisioning the same tenant updates its domain.
	err := db.WithTenantTx(r.Context(), s.d.Pool, body.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `INSERT INTO tenant_settings (tenant_id, domain) VALUES ($1, $2)
			ON CONFLICT (tenant_id) DO UPDATE SET domain = EXCLUDED.domain, updated_at = now()
			RETURNING jsonb_build_object('tenant_id', tenant_id, 'domain', domain, 'plan', plan, 'disabled_at', disabled_at)`,
			body.TenantID, body.Domain)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, out)
}

func (s *Server) adminListTenants(w http.ResponseWriter, r *http.Request) error {
	return s.sysList(`
SELECT t.tenant_id, t.domain, t.plan, t.disabled_at, t.created_at, t.projects,
  (SELECT count(*) FROM gh_installations i WHERE i.tenant_id = t.tenant_id) AS installations
FROM depguard_admin_tenants() t`,
		filterSpec{ilike: map[string]string{"domain": "t.domain"}}, "t.created_at DESC, t.tenant_id", nil)(w, r)
}

func (s *Server) adminPatchTenant(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Disabled *bool `json:"disabled"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if body.Disabled == nil {
		return badRequest("disabled is required")
	}
	var out json.RawMessage
	err := db.WithTenantTx(r.Context(), s.d.Pool, r.PathValue("id"), func(tx pgx.Tx) error {
		var err error
		out, err = one(r.Context(), tx, `UPDATE tenant_settings SET updated_at = now(),
			disabled_at = CASE WHEN $1 THEN COALESCE(disabled_at, now()) ELSE NULL END
			RETURNING jsonb_build_object('tenant_id', tenant_id, 'domain', domain, 'plan', plan, 'disabled_at', disabled_at)`, *body.Disabled)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminListInstallations(w http.ResponseWriter, r *http.Request) error {
	return s.sysList(`
SELECT i.id, i.account_login, i.account_type, i.account_id, i.tenant_id, i.status, i.created_at, i.updated_at,
  (SELECT count(*) FROM gh_repositories g WHERE g.installation_id = i.id AND g.removed_at IS NULL) AS repos
FROM gh_installations i`,
		filterSpec{eq: map[string]string{"status": "t.status", "tenant_id": "t.tenant_id"}, ilike: map[string]string{"account": "t.account_login"}},
		"t.created_at DESC, t.id", nil)(w, r)
}

func installationID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return 0, badRequest("invalid installation id")
	}
	return id, nil
}

func (s *Server) adminLinkInstallation(w http.ResponseWriter, r *http.Request) error {
	if s.d.Jobs == nil {
		return unavailable("job queue")
	}
	id, err := installationID(r)
	if err != nil {
		return err
	}
	var body struct {
		TenantID string `json:"tenant_id"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if body.TenantID == "" {
		return badRequest("tenant_id is required")
	}
	err = db.WithTenantTx(r.Context(), s.d.Pool, body.TenantID, func(tx pgx.Tx) error {
		var x int
		return tx.QueryRow(r.Context(), `SELECT 1 FROM tenant_settings`).Scan(&x)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errf(http.StatusNotFound, "tenant not provisioned")
	}
	if err != nil {
		return err
	}
	err = s.sysTx(r, func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(r.Context(), `UPDATE gh_installations SET tenant_id = $2, status = 'linked', updated_at = now()
			WHERE id = $1 AND status <> 'deleted' RETURNING status`, id, body.TenantID).Scan(&status)
		if err != nil {
			return err
		}
		_, err = s.d.Jobs.InsertTx(r.Context(), tx, jobs.SyncInstallation{InstallationID: id}, nil)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"id": id, "tenant_id": body.TenantID, "status": "linked"})
}

func (s *Server) adminUnlinkInstallation(w http.ResponseWriter, r *http.Request) error {
	id, err := installationID(r)
	if err != nil {
		return err
	}
	err = s.sysTx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE gh_installations SET tenant_id = NULL, status = 'pending', updated_at = now()
			WHERE id = $1 AND status <> 'deleted'`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return errNotFound
		}
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"id": id, "tenant_id": nil, "status": "pending"})
}

func (s *Server) adminFeeds(w http.ResponseWriter, r *http.Request) error {
	if s.d.FeedsStatus == nil {
		return unavailable("feeds status")
	}
	st, err := s.d.FeedsStatus(r.Context())
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, st)
}

func (s *Server) adminWebhooks(w http.ResponseWriter, r *http.Request) error {
	return s.sysList(`SELECT delivery_id, event, action, installation_id, repository, status, error, received_at FROM webhook_deliveries`,
		filterSpec{eq: map[string]string{"status": "t.status", "event": "t.event"}, dateCol: "t.received_at"},
		"t.received_at DESC, t.delivery_id", nil)(w, r)
}

func (s *Server) adminRedeliver(w http.ResponseWriter, r *http.Request) error {
	if s.d.Redeliver == nil {
		return unavailable("github app")
	}
	id := r.PathValue("delivery_id")
	err := s.sysTx(r, func(tx pgx.Tx) error {
		var x int
		return tx.QueryRow(r.Context(), `SELECT 1 FROM webhook_deliveries WHERE delivery_id = $1`, id).Scan(&x)
	})
	if err != nil {
		return err
	}
	if err := s.d.Redeliver(r.Context(), id); err != nil {
		return errf(http.StatusBadGateway, "redeliver failed: %v", err)
	}
	return writeJSON(w, http.StatusAccepted, map[string]string{"delivery_id": id, "status": "redelivery requested"})
}

func (s *Server) adminFailedJobs(w http.ResponseWriter, r *http.Request) error {
	return s.sysList(`SELECT id, kind, queue, state::text AS state, attempt, max_attempts, args, errors,
  created_at, attempted_at, finalized_at FROM river_job WHERE state IN ('retryable', 'discarded')`,
		filterSpec{eq: map[string]string{"kind": "t.kind", "state": "t.state"}, dateCol: "t.created_at"},
		"t.id DESC", nil)(w, r)
}
