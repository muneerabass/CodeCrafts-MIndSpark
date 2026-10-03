package ghapp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/google/go-github/v92/github"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// Deps for the webhook handler. River may be an insert-only client.
type Deps struct {
	Pool   *pgxpool.Pool
	River  *river.Client[pgx.Tx]
	Config Config
	Logger *slog.Logger
}

// Delivery statuses in webhook_deliveries.
const (
	StatusEnqueued  = "enqueued"  // a job was enqueued
	StatusProcessed = "processed" // handled without a job (e.g. installation deleted)
	StatusIgnored   = "ignored"   // intentionally skipped (unlinked, draft, irrelevant)
	StatusFailed    = "failed"
)

// JobOpts: 5 attempts, dedupe identical args while a job is in flight.
// Callers outside ghapp (api manual scans) should use it too.
var JobOpts = &river.InsertOpts{
	MaxAttempts: 5,
	UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
		rivertype.JobStateRetryable, rivertype.JobStateScheduled,
	}},
}

// NewWebhookHandler serves POST /github/webhook.
func NewWebhookHandler(d Deps) http.Handler {
	d.Config = d.Config.withDefaults()
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 25<<20)
		payload, err := github.ValidatePayload(r, []byte(d.Config.WebhookSecret))
		if err != nil || d.Config.WebhookSecret == "" {
			reply(w, http.StatusUnauthorized, "invalid signature")
			return
		}
		event, id := github.WebHookType(r), github.DeliveryID(r)
		if id == "" || event == "" {
			reply(w, http.StatusBadRequest, "missing delivery headers")
			return
		}
		status, err := d.process(r.Context(), id, event, payload)
		if err != nil {
			d.Logger.Error("webhook failed", "delivery", id, "event", event, "err", err)
			d.recordFailure(r.Context(), id, event, err)
			reply(w, http.StatusInternalServerError, "processing failed")
			return
		}
		code := http.StatusAccepted
		if status == "duplicate" {
			code = http.StatusOK
		}
		reply(w, code, status)
	})
}

func reply(w http.ResponseWriter, code int, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
}

// meta is what we record for every delivery.
type meta struct {
	action string
	instID int64
	repo   string
}

func metaOf(ev any) meta {
	var m meta
	if v, ok := ev.(interface{ GetAction() string }); ok {
		m.action = v.GetAction()
	}
	if v, ok := ev.(interface{ GetInstallation() *github.Installation }); ok {
		m.instID = v.GetInstallation().GetID()
	}
	switch e := ev.(type) {
	case *github.PushEvent:
		m.repo = e.GetRepo().GetFullName()
	case interface{ GetRepo() *github.Repository }:
		m.repo = e.GetRepo().GetFullName()
	}
	return m
}

func (d Deps) process(ctx context.Context, id, event string, payload []byte) (string, error) {
	ev, perr := github.ParseWebHook(event, payload)
	m := metaOf(ev)
	status := "duplicate"
	err := db.WithSystemTx(ctx, d.Pool, func(tx pgx.Tx) error {
		// A failed delivery may be redelivered and processed again.
		tag, err := tx.Exec(ctx, `INSERT INTO webhook_deliveries (delivery_id, event, action, installation_id, repository)
			VALUES ($1, $2, NULLIF($3,''), NULLIF($4,0), NULLIF($5,''))
			ON CONFLICT (delivery_id) DO UPDATE SET status='received', error=NULL, received_at=now()
			WHERE webhook_deliveries.status = 'failed'`, id, event, m.action, m.instID, m.repo)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		status = StatusIgnored
		if perr == nil {
			if status, err = d.dispatch(ctx, tx, ev); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET status=$2 WHERE delivery_id=$1`, id, status)
		return err
	})
	return status, err
}

func (d Deps) recordFailure(ctx context.Context, id, event string, cause error) {
	err := db.WithSystemTx(context.WithoutCancel(ctx), d.Pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO webhook_deliveries (delivery_id, event, status, error) VALUES ($1,$2,'failed',$3)
			ON CONFLICT (delivery_id) DO UPDATE SET status='failed', error=EXCLUDED.error`, id, event, cause.Error())
		return err
	})
	if err != nil {
		d.Logger.Error("record webhook failure", "delivery", id, "err", err)
	}
}

func (d Deps) dispatch(ctx context.Context, tx pgx.Tx, ev any) (string, error) {
	switch e := ev.(type) {
	case *github.InstallationEvent:
		return d.onInstallation(ctx, tx, e)
	case *github.InstallationRepositoriesEvent:
		if err := UpsertInstallation(ctx, tx, e.GetInstallation()); err != nil {
			return "", err
		}
		for _, r := range e.RepositoriesAdded {
			if err := UpsertRepo(ctx, tx, e.GetInstallation().GetID(), r); err != nil {
				return "", err
			}
		}
		for _, r := range e.RepositoriesRemoved {
			if _, err := tx.Exec(ctx, `UPDATE gh_repositories SET removed_at=now() WHERE id=$1`, r.GetID()); err != nil {
				return "", err
			}
		}
		return d.insert(ctx, tx, jobs.SyncInstallation{InstallationID: e.GetInstallation().GetID()})
	case *github.PullRequestEvent:
		return d.onPullRequest(ctx, tx, e)
	case *github.PushEvent:
		return d.onPush(ctx, tx, e)
	case *github.CheckRunEvent:
		return d.onCheckRun(ctx, tx, e)
	}
	return StatusIgnored, nil
}

func (d Deps) insert(ctx context.Context, tx pgx.Tx, args river.JobArgs) (string, error) {
	if _, err := d.River.InsertTx(ctx, tx, args, JobOpts); err != nil {
		return "", err
	}
	return StatusEnqueued, nil
}

// UpsertInstallation records an installation. A new one is pending unless an
// installation for the same GitHub account was linked to a tenant before.
func UpsertInstallation(ctx context.Context, tx pgx.Tx, in *github.Installation) error {
	acct := in.GetAccount()
	_, err := tx.Exec(ctx, `INSERT INTO gh_installations (id, account_login, account_type, account_id, tenant_id, status)
		SELECT $1, $2, $3, $4, t.tenant_id, CASE WHEN t.tenant_id IS NULL THEN 'pending' ELSE 'linked' END
		FROM (SELECT (SELECT tenant_id FROM gh_installations WHERE account_id=$4 AND id<>$1 AND tenant_id IS NOT NULL
		              ORDER BY (status='linked') DESC, updated_at DESC LIMIT 1) AS tenant_id) t
		ON CONFLICT (id) DO UPDATE SET account_login=EXCLUDED.account_login, account_type=EXCLUDED.account_type, updated_at=now()`,
		in.GetID(), acct.GetLogin(), acct.GetType(), acct.GetID())
	return err
}

// UpsertRepo records a repository of an installation (clears removed_at).
func UpsertRepo(ctx context.Context, tx pgx.Tx, installationID int64, r *github.Repository) error {
	_, err := tx.Exec(ctx, `INSERT INTO gh_repositories (id, installation_id, full_name, default_branch, private)
		VALUES ($1, $2, $3, COALESCE(NULLIF($4,''),'main'), $5)
		ON CONFLICT (id) DO UPDATE SET installation_id=EXCLUDED.installation_id, full_name=EXCLUDED.full_name,
		  private=EXCLUDED.private, removed_at=NULL,
		  default_branch=CASE WHEN $4 <> '' THEN EXCLUDED.default_branch ELSE gh_repositories.default_branch END`,
		r.GetID(), installationID, r.GetFullName(), r.GetDefaultBranch(), r.GetPrivate())
	return err
}

func (d Deps) onInstallation(ctx context.Context, tx pgx.Tx, e *github.InstallationEvent) (string, error) {
	id := e.GetInstallation().GetID()
	var q string
	switch e.GetAction() {
	case "created":
		if err := UpsertInstallation(ctx, tx, e.GetInstallation()); err != nil {
			return "", err
		}
		for _, r := range e.Repositories {
			if err := UpsertRepo(ctx, tx, id, r); err != nil {
				return "", err
			}
		}
		return d.insert(ctx, tx, jobs.SyncInstallation{InstallationID: id})
	case "deleted":
		q = `UPDATE gh_installations SET status='deleted', updated_at=now() WHERE id=$1`
	case "suspend":
		q = `UPDATE gh_installations SET status='suspended', updated_at=now() WHERE id=$1`
	case "unsuspend":
		q = `UPDATE gh_installations SET status=CASE WHEN tenant_id IS NULL THEN 'pending' ELSE 'linked' END, updated_at=now() WHERE id=$1`
	default:
		return StatusIgnored, nil
	}
	if _, err := tx.Exec(ctx, q, id); err != nil {
		return "", err
	}
	return StatusProcessed, nil
}

// linkedTenant returns the tenant of a linked, enabled installation and that
// tenant's draft-PR preference; ok=false means "do nothing".
func linkedTenant(ctx context.Context, tx pgx.Tx, installationID int64) (tenant string, scanDrafts, ok bool, err error) {
	err = tx.QueryRow(ctx, `SELECT tenant_id FROM gh_installations WHERE id=$1 AND status='linked' AND tenant_id IS NOT NULL`,
		installationID).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	// tenant_settings is RLS-protected: scope this transaction to the tenant.
	if _, err = tx.Exec(ctx, `SELECT set_config('app.tenant', $1, true)`, tenant); err != nil {
		return "", false, false, err
	}
	var disabled bool
	err = tx.QueryRow(ctx, `SELECT scan_draft_prs, disabled_at IS NOT NULL FROM tenant_settings WHERE tenant_id=$1`, tenant).
		Scan(&scanDrafts, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant, false, true, nil
	}
	return tenant, scanDrafts, err == nil && !disabled, err
}

var prActions = map[string]bool{"opened": true, "synchronize": true, "reopened": true, "ready_for_review": true}

func (d Deps) onPullRequest(ctx context.Context, tx pgx.Tx, e *github.PullRequestEvent) (string, error) {
	if !prActions[e.GetAction()] {
		return StatusIgnored, nil
	}
	_, scanDrafts, ok, err := linkedTenant(ctx, tx, e.GetInstallation().GetID())
	if err != nil || !ok {
		return StatusIgnored, err
	}
	pr := e.GetPullRequest()
	if pr.GetDraft() && !scanDrafts {
		return StatusIgnored, nil
	}
	if err := UpsertRepo(ctx, tx, e.GetInstallation().GetID(), e.GetRepo()); err != nil {
		return "", err
	}
	return d.insert(ctx, tx, jobs.ScanPullRequest{
		InstallationID: e.GetInstallation().GetID(),
		RepoID:         e.GetRepo().GetID(),
		RepoFullName:   e.GetRepo().GetFullName(),
		PRNumber:       pr.GetNumber(),
		BaseSHA:        pr.GetBase().GetSHA(),
		HeadSHA:        pr.GetHead().GetSHA(),
		BaseRef:        pr.GetBase().GetRef(),
		HeadRef:        pr.GetHead().GetRef(),
		IsDraft:        pr.GetDraft(),
	})
}

func (d Deps) onPush(ctx context.Context, tx pgx.Tx, e *github.PushEvent) (string, error) {
	repo := e.GetRepo()
	branch, isBranch := strings.CutPrefix(e.GetRef(), "refs/heads/")
	if !isBranch || e.GetDeleted() || branch != repo.GetDefaultBranch() {
		return StatusIgnored, nil
	}
	tenant, _, ok, err := linkedTenant(ctx, tx, e.GetInstallation().GetID())
	if err != nil || !ok {
		return StatusIgnored, err
	}
	return d.insert(ctx, tx, jobs.ScanRepository{
		TenantID:       tenant,
		InstallationID: e.GetInstallation().GetID(),
		RepoID:         repo.GetID(),
		RepoFullName:   repo.GetFullName(),
		Ref:            branch,
		SHA:            e.GetAfter(),
		Trigger:        "push",
	})
}

func (d Deps) onCheckRun(ctx context.Context, tx pgx.Tx, e *github.CheckRunEvent) (string, error) {
	cr := e.GetCheckRun()
	if e.GetAction() != "rerequested" || cr.GetName() != d.Config.CheckRunName ||
		(d.Config.AppID != 0 && cr.GetApp().GetID() != 0 && cr.GetApp().GetID() != d.Config.AppID) || len(cr.PullRequests) == 0 {
		return StatusIgnored, nil
	}
	if _, _, ok, err := linkedTenant(ctx, tx, e.GetInstallation().GetID()); err != nil || !ok {
		return StatusIgnored, err
	}
	pr := cr.PullRequests[0]
	return d.insert(ctx, tx, jobs.ScanPullRequest{
		InstallationID: e.GetInstallation().GetID(),
		RepoID:         e.GetRepo().GetID(),
		RepoFullName:   e.GetRepo().GetFullName(),
		PRNumber:       pr.GetNumber(),
		BaseSHA:        pr.GetBase().GetSHA(),
		HeadSHA:        cr.GetHeadSHA(),
		BaseRef:        pr.GetBase().GetRef(),
		HeadRef:        pr.GetHead().GetRef(),
	})
}
