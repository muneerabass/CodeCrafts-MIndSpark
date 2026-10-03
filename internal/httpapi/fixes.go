package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/depguard/depguard/internal/engine"
	"github.com/depguard/depguard/internal/fixer"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/render"
	"github.com/depguard/depguard/internal/teamcfg"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

func (s *Server) listFixes(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `
SELECT f.id, f.project_id, p.name AS project, f.ecosystem, f.name, f.from_version, f.to_version, f.manifest_path, f.direct,
  f.advisories, f.branch, f.pr_number, f.pr_url, f.status, f.error, f.trigger, f.created_by, f.created_at, f.updated_at
FROM fix_prs f JOIN projects p ON p.id = f.project_id`,
		filterSpec{eq: map[string]string{"project_id": "t.project_id", "status": "t.status", "name": "t.name"}},
		"t.created_at DESC, t.id", nil)(w, r)
}

var versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_~-]{0,63}$`)

// createFix queues a fix pull request for a vulnerable package of a project.
func (s *Server) createFix(w http.ResponseWriter, r *http.Request) error {
	if s.d.Jobs == nil {
		return unavailable("job queue")
	}
	var body struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Version   string `json:"version"`
		Manifest  string `json:"manifest_path"`
		ToVersion string `json:"to_version"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if body.Name == "" || body.Version == "" || body.Manifest == "" || (body.ToVersion != "" && !versionRe.MatchString(body.ToVersion)) {
		return badRequest("ecosystem, name, version and manifest_path are required")
	}
	p := principal(r)
	projectID := r.PathValue("id")
	var out map[string]any
	err := s.tx(r, func(tx pgx.Tx) error {
		// The package must be a current vulnerable package of the project with a known fix.
		rows, err := tx.Query(r.Context(), `SELECT pv.id FROM project_versions pv WHERE pv.project_id=$1 AND pv.last_scan_id IS NOT NULL`, projectID)
		if err != nil {
			return err
		}
		vids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		var cand *engine.FixCandidate
		for _, v := range vids {
			cs, err := engine.FixCandidates(r.Context(), tx, v)
			if err != nil {
				return err
			}
			for i, c := range cs {
				if strings.EqualFold(c.Ecosystem, body.Ecosystem) && c.Name == body.Name && c.Version == body.Version && c.Manifest == body.Manifest {
					cand = &cs[i]
				}
			}
		}
		if cand == nil {
			return errf(http.StatusUnprocessableEntity, "%s@%s has no known fixed version in this project", body.Name, body.Version)
		}
		to := cand.FixedIn
		if body.ToVersion != "" {
			to = body.ToVersion
		}
		cmd := render.UpgradeCommand(cand.Ecosystem, cand.Name, to, cand.Manifest)
		if fixer.Inputs(cand.Ecosystem, cand.Manifest) == nil {
			out = map[string]any{"status": "unsupported", "to_version": to, "command": cmd,
				"error": "Automatic fixes are not supported for this lockfile yet. Run the command instead."}
			return nil
		}
		var existing string
		err = tx.QueryRow(r.Context(), `SELECT id FROM fix_prs WHERE project_id=$1 AND ecosystem=$2 AND name=$3 AND to_version=$4 AND manifest_path=$5
			AND status IN ('queued','open')`, projectID, cand.Ecosystem, cand.Name, to, cand.Manifest).Scan(&existing)
		if err == nil {
			out = map[string]any{"id": existing, "status": "exists", "to_version": to, "command": cmd}
			return nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		id := ids.New()
		if _, err := tx.Exec(r.Context(), `INSERT INTO fix_prs (id, tenant_id, project_id, ecosystem, name, from_version, to_version, manifest_path, direct, advisories, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, id, p.TenantID, projectID, cand.Ecosystem, cand.Name, cand.Version, to, cand.Manifest,
			cand.Direct, cand.Advisories, firstNonEmpty(p.Email, p.Name, p.UserID)); err != nil {
			return err
		}
		if _, err := s.d.Jobs.InsertTx(r.Context(), tx, jobs.CreateFixPR{TenantID: p.TenantID, FixID: id}, &river.InsertOpts{MaxAttempts: 3}); err != nil {
			return err
		}
		out = map[string]any{"id": id, "status": "queued", "to_version": to, "command": cmd}
		return nil
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusAccepted, out)
}

func (s *Server) getFixSettings(w http.ResponseWriter, r *http.Request) error {
	var raw []byte
	err := s.tx(r, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT fix_settings FROM tenant_settings`).Scan(&raw)
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return writeJSON(w, http.StatusOK, teamcfg.ParseFix(raw))
}

func (s *Server) putFixSettings(w http.ResponseWriter, r *http.Request) error {
	set := teamcfg.DefaultFix()
	if err := decode(w, r, jsonLimit, &set); err != nil {
		return err
	}
	if err := set.Validate(); err != nil {
		return badRequest("%v", err)
	}
	b, _ := json.Marshal(set)
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE tenant_settings SET fix_settings=$1, updated_at=now()`, b)
		if err == nil && tag.RowsAffected() == 0 {
			return errf(http.StatusNotFound, "tenant not provisioned")
		}
		return err
	})
	if err != nil {
		return err
	}
	return s.getFixSettings(w, r)
}
