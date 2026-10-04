package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/prsettings"
)

// prListSQL: one row per pull request with its project, latest scan and review.
const prListSQL = `
SELECT pr.id, pr.repo_full_name, pr.number, pr.title, pr.author_login, pr.author_avatar, pr.html_url, pr.state, pr.draft,
  pr.base_ref, pr.head_ref, pr.head_sha, pr.latest_scan_id, pr.urgency, pr.urgency_level, pr.reasons, pr.labels,
  pr.gh_created_at, pr.gh_updated_at, pr.closed_at, pr.merged_at,
  CASE pr.state WHEN 'open' THEN 0 ELSE 1 END AS state_rank,
  p.id AS project_id, jsonb_build_object('id', p.id, 'name', p.name) AS project,
  CASE WHEN s.id IS NULL THEN NULL ELSE jsonb_build_object('id', s.id, 'status', s.status, 'conclusion', s.conclusion,
    'vulns', s.vulns_count, 'violations', s.violations_count, 'malicious', s.malicious_count, 'suspicious', s.suspicious_count) END AS scan,
  CASE WHEN rv.id IS NULL THEN NULL ELSE jsonb_build_object('ai_status', rv.ai_status, 'findings', jsonb_array_length(rv.findings),
    'ai_risk', rv.ai_risk) END AS review
FROM pull_requests pr
LEFT JOIN projects p ON p.gh_repo_id = pr.repo_id
LEFT JOIN scans s ON s.id = pr.latest_scan_id
LEFT JOIN pr_reviews rv ON rv.pr_id = pr.id AND rv.head_sha = pr.head_sha`

func prFilters(r *http.Request, w *where) error {
	q := r.URL.Query()
	switch st := q.Get("state"); st {
	case "", "open":
		w.add("t.state = 'open'")
	case "all":
	case "closed", "merged":
		w.add("t.state = ?", st)
	default:
		return badRequest("state must be open, closed, merged or all")
	}
	if l := q.Get("level"); l != "" {
		w.add("t.urgency_level = ?", l)
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		w.add("(t.title ILIKE ? OR t.repo_full_name ILIKE ? OR t.number::text = ?)", "%"+v+"%", "%"+v+"%", v)
	}
	if v := q.Get("label"); v != "" {
		w.add("? = ANY(t.labels)", v)
	}
	return nil
}

func prOrder(r *http.Request) string {
	if r.URL.Query().Get("sort") == "updated" {
		return "t.gh_updated_at DESC NULLS LAST, t.id"
	}
	// Open first, then the most urgent, then the most recently updated.
	return "t.state_rank, t.urgency DESC, t.gh_updated_at DESC NULLS LAST, t.id"
}

// listPullRequests is the team inbox.
func (s *Server) listPullRequests(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", prListSQL, filterSpec{eq: map[string]string{"project_id": "t.project_id", "author": "t.author_login"}},
		prOrder(r), prFilters, "state_rank", "project_id")(w, r)
}

// projectPullRequests lists one project's pull requests.
func (s *Server) projectPullRequests(w http.ResponseWriter, r *http.Request) error {
	project := r.PathValue("id")
	return s.listHandler("", prListSQL, filterSpec{eq: map[string]string{"author": "t.author_login"}}, prOrder(r),
		func(r *http.Request, w *where) error {
			w.add("t.project_id = ?", project)
			return prFilters(r, w)
		}, "state_rank", "project_id")(w, r)
}

// prSummary counts open pull requests by urgency level.
func (s *Server) prSummary(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		args := []any{}
		cond := ""
		if p := r.URL.Query().Get("project_id"); p != "" {
			cond, args = " AND repo_id = (SELECT gh_repo_id FROM projects WHERE id = $1)", append(args, p)
		}
		out, err = one(r.Context(), tx, `SELECT jsonb_build_object(
			'open', count(*) FILTER (WHERE state='open'),
			'by_level', jsonb_build_object(
			  'critical', count(*) FILTER (WHERE state='open' AND urgency_level='critical'),
			  'high', count(*) FILTER (WHERE state='open' AND urgency_level='high'),
			  'medium', count(*) FILTER (WHERE state='open' AND urgency_level='medium'),
			  'low', count(*) FILTER (WHERE state='open' AND urgency_level='low'),
			  'clean', count(*) FILTER (WHERE state='open' AND urgency_level='clean'),
			  'pending', count(*) FILTER (WHERE state='open' AND urgency_level='pending')),
			'merged_with_issues', count(*) FILTER (WHERE state='merged' AND urgency_level IN ('critical','high')))
			FROM pull_requests WHERE true`+cond, args...)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// prID resolves {id}/{number} to the pull request id (404 if missing).
func prID(r *http.Request, tx pgx.Tx) (string, error) {
	n, err := strconv.Atoi(r.PathValue("number"))
	if err != nil {
		return "", errNotFound
	}
	var id string
	err = tx.QueryRow(r.Context(), `SELECT pr.id FROM pull_requests pr JOIN projects p ON p.gh_repo_id = pr.repo_id
		WHERE p.id = $1 AND pr.number = $2`, r.PathValue("id"), n).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errNotFound
	}
	return id, err
}

// getPullRequest is the PR detail: metadata, urgency, latest scan, review, history and activity.
func (s *Server) getPullRequest(w http.ResponseWriter, r *http.Request) error {
	var out json.RawMessage
	err := s.tx(r, func(tx pgx.Tx) error {
		id, err := prID(r, tx)
		if err != nil {
			return err
		}
		out, err = one(r.Context(), tx, `
SELECT to_jsonb(t) || jsonb_build_object(
  'summary', (SELECT pr_summary FROM scans WHERE id = t.latest_scan_id),
  'review', (SELECT jsonb_build_object('head_sha', rv.head_sha, 'findings', rv.findings, 'labels', rv.labels, 'files_reviewed', rv.files_reviewed,
      'truncated', rv.truncated, 'ai_status', rv.ai_status, 'ai_note', rv.ai_note, 'ai_model', rv.ai_model, 'ai_summary', rv.ai_summary,
      'ai_risk', rv.ai_risk, 'updated_at', rv.updated_at)
    FROM pr_reviews rv WHERE rv.pr_id = t.id AND rv.head_sha = t.head_sha),
  'history', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', s.id, 'head_sha', s.head_sha, 'status', s.status, 'conclusion', s.conclusion,
      'vulns', s.vulns_count, 'violations', s.violations_count, 'malicious', s.malicious_count, 'created_at', s.created_at) ORDER BY s.created_at DESC)
    FROM scans s WHERE s.project_id = t.project_id AND s.pr_number = t.number AND s.trigger = 'pull_request'), '[]'::jsonb),
  'vault_matches', COALESCE((SELECT jsonb_agg(DISTINCT jsonb_build_object('fingerprint', f->>'fingerprint', 'project_id', vi.project_id,
      'project', vp.name, 'item', vi.name, 'key', fp->>'name'))
    FROM pr_reviews rv CROSS JOIN jsonb_array_elements(rv.findings) f
    JOIN vault_items vi ON vi.fingerprints @> jsonb_build_array(jsonb_build_object('sha256', f->>'fingerprint'))
    CROSS JOIN jsonb_array_elements(vi.fingerprints) fp JOIN projects vp ON vp.id = vi.project_id
    WHERE rv.pr_id = t.id AND rv.head_sha = t.head_sha AND f ? 'fingerprint' AND fp->>'sha256' = f->>'fingerprint'), '[]'::jsonb),
  'activity', COALESCE((SELECT jsonb_agg(jsonb_build_object('id', a.id, 'kind', a.kind, 'body', a.body, 'status', a.status,
      'actor', a.actor_email, 'error', a.error, 'created_at', a.created_at) ORDER BY a.created_at DESC)
    FROM pr_activity a WHERE a.pr_id = t.id), '[]'::jsonb))
FROM (`+prListSQL+`) t WHERE t.id = $1`, id)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

var prActionKinds = map[string]string{"comment": "comment", "review": "request_changes", "rescan": "rescan", "ai-review": "ai_review"}

// prAction queues a dashboard action; the worker performs it on GitHub.
func (s *Server) prAction(w http.ResponseWriter, r *http.Request) error {
	kind := prActionKinds[r.PathValue("action")]
	if kind == "" {
		return errNotFound
	}
	if s.d.Jobs == nil {
		return unavailable("job queue")
	}
	var body struct {
		Body string `json:"body"`
	}
	if r.ContentLength != 0 {
		if err := decode(w, r, jsonLimit, &body); err != nil {
			return err
		}
	}
	body.Body = strings.TrimSpace(body.Body)
	if (kind == "comment" || kind == "request_changes") && (body.Body == "" || len(body.Body) > 60000) {
		return badRequest("body is required (at most 60000 characters)")
	}
	p := principal(r)
	actID := ids.New()
	err := s.tx(r, func(tx pgx.Tx) error {
		id, err := prID(r, tx)
		if err != nil {
			return err
		}
		var state string
		if err := tx.QueryRow(r.Context(), `SELECT state FROM pull_requests WHERE id=$1`, id).Scan(&state); err != nil {
			return err
		}
		if state != "open" {
			return badRequest("this pull request is %s", state)
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO pr_activity (id, tenant_id, pr_id, actor_email, kind, body) VALUES ($1,$2,$3,$4,$5,$6)`,
			actID, p.TenantID, id, firstNonEmpty(p.Email, p.Name, p.UserID), kind, body.Body); err != nil {
			return err
		}
		_, err = s.d.Jobs.InsertTx(r.Context(), tx, jobs.PRAction{TenantID: p.TenantID, ActivityID: actID}, nil)
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusAccepted, map[string]string{"activity_id": actID, "status": "queued"})
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// getPRSettings returns the team's pull request settings and whether AI review is available.
func (s *Server) getPRSettings(w http.ResponseWriter, r *http.Request) error {
	var raw []byte
	err := s.tx(r, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT pr_settings FROM tenant_settings`).Scan(&raw)
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return writeJSON(w, http.StatusOK, map[string]any{"settings": prsettings.Parse(raw), "ai_configured": os.Getenv("AI_REVIEW_CONFIGURED") == "1",
		"ai_models": os.Getenv("DEPGUARD_AI_MODELS")})
}

func (s *Server) putPRSettings(w http.ResponseWriter, r *http.Request) error {
	set := prsettings.Default()
	if err := decode(w, r, jsonLimit, &set); err != nil {
		return err
	}
	if err := set.Validate(); err != nil {
		return badRequest("%v", err)
	}
	b, _ := json.Marshal(set)
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE tenant_settings SET pr_settings=$1, updated_at=now()`, b)
		if err == nil && tag.RowsAffected() == 0 {
			return errf(http.StatusNotFound, "tenant not provisioned")
		}
		return err
	})
	if err != nil {
		return err
	}
	return s.getPRSettings(w, r)
}
