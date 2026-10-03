package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/depguard/depguard/internal/aireview"
	"github.com/depguard/depguard/internal/ghapp"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/llm"
	"github.com/depguard/depguard/internal/prrank"
	"github.com/depguard/depguard/internal/prreview"
	"github.com/depguard/depguard/internal/prsettings"
	"github.com/depguard/depguard/internal/render"
)

// prRow is a pull_requests row plus its project.
type prRow struct {
	ID, RepoFull, Title, Author, HTMLURL, State string
	HeadSHA, BaseSHA, BaseRef, HeadRef          string
	RepoID, InstallationID                      int64
	Number                                      int
	Draft                                       bool
	OpenedAt                                    time.Time
	LatestScanID                                string
	Level                                       string
	ProjectID                                   string
}

func loadPR(ctx context.Context, tx pgx.Tx, id string) (prRow, error) {
	var r prRow
	var opened *time.Time
	var latest, project *string
	var inst *int64
	err := tx.QueryRow(ctx, `SELECT pr.id, pr.repo_full_name, pr.title, pr.author_login, pr.html_url, pr.state, pr.head_sha, pr.base_sha,
		  pr.base_ref, pr.head_ref, pr.repo_id, pr.installation_id, pr.number, pr.draft, pr.gh_created_at, pr.latest_scan_id, pr.urgency_level,
		  (SELECT p.id FROM projects p WHERE p.gh_repo_id = pr.repo_id ORDER BY p.created_at LIMIT 1)
		FROM pull_requests pr WHERE pr.id = $1`, id).Scan(&r.ID, &r.RepoFull, &r.Title, &r.Author, &r.HTMLURL, &r.State, &r.HeadSHA, &r.BaseSHA,
		&r.BaseRef, &r.HeadRef, &r.RepoID, &inst, &r.Number, &r.Draft, &opened, &latest, &r.Level, &project)
	if opened != nil {
		r.OpenedAt = *opened
	}
	if latest != nil {
		r.LatestScanID = *latest
	}
	if project != nil {
		r.ProjectID = *project
	}
	if inst != nil {
		r.InstallationID = *inst
	}
	return r, err
}

func loadPRSettings(ctx context.Context, tx pgx.Tx) prsettings.Settings {
	var raw []byte
	_ = tx.QueryRow(ctx, `SELECT pr_settings FROM tenant_settings`).Scan(&raw)
	return prsettings.Parse(raw)
}

// loadReview returns the review of a PR head commit (zero value if none).
func loadReview(ctx context.Context, tx pgx.Tx, prID, head string) (render.PRReview, error) {
	var rv render.PRReview
	var findings []byte
	err := tx.QueryRow(ctx, `SELECT findings, labels, ai_status, ai_note, ai_model, ai_summary, files_reviewed, truncated
		FROM pr_reviews WHERE pr_id=$1 AND head_sha=$2`, prID, head).
		Scan(&findings, &rv.Labels, &rv.AIStatus, &rv.AINote, &rv.AIModel, &rv.AISum, &rv.Files, &rv.Truncate)
	if errors.Is(err, pgx.ErrNoRows) {
		return render.PRReview{AIStatus: "skipped"}, nil
	}
	if err != nil {
		return rv, err
	}
	_ = json.Unmarshal(findings, &rv.Findings)
	return rv, nil
}

// lateFindings adds results that arrive after the scan (guarddog verdicts) to the summary.
func lateFindings(ctx context.Context, tx pgx.Tx, scanID string, s *render.PRSummary) error {
	rows, err := tx.Query(ctx, `SELECT c.name, c.version, v.summary, v.severity, v.blocking FROM policy_violations v
		JOIN components c ON c.id = v.component_id WHERE v.scan_id=$1 AND v.rule_name='unusual-behaviour'`, scanID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, version, summary, sev string
		var blocking bool
		if err := rows.Scan(&name, &version, &summary, &sev, &blocking); err != nil {
			return err
		}
		title := fmt.Sprintf("`%s@%s`: %s", name, version, render.Escape(summary))
		if slices.ContainsFunc(s.Fixes, func(f render.FixItem) bool { return f.Title == title }) {
			continue
		}
		s.Fixes = append([]render.FixItem{{Kind: "suspicious", Severity: sev, Blocking: blocking, Title: title,
			Note: "Install-time behaviour flagged by malware heuristics (guarddog). Review the package before merging."}}, s.Fixes...)
		if blocking {
			s.Checks["suspicious"] = render.StateFail
		} else if s.Checks["suspicious"] != render.StateFail {
			s.Checks["suspicious"] = render.StateWarn
		}
		if !slices.Contains(s.Labels, "suspicious-package") {
			s.Labels = append(s.Labels, "suspicious-package")
		}
	}
	return rows.Err()
}

func policyNote(st settings) string {
	parts := []string{map[bool]string{true: "block mode on", false: "warn only"}[st.BlockMode]}
	if p := st.Policy.Presets; p != nil {
		parts = append(parts, "vulnerabilities ≥ "+strings.ToLower(p.Vulnerability.MinRisk))
		if n := len(p.Packages); n > 0 {
			parts = append(parts, fmt.Sprintf("%d package rules", n))
		}
	}
	return strings.Join(parts, " · ")
}

// refreshPR ranks the PR from its latest scan and review, then updates the
// PR comment, labels and (optionally) a request-changes review on GitHub.
func (d Deps) refreshPR(ctx context.Context, gh *github.Client, tenant, prID string) error {
	var (
		pr        prRow
		st        settings
		ps        prsettings.Settings
		sum       render.PRSummary
		rv        render.PRReview
		commentID int64
		commits   []string
		concl     string
	)
	err := withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		var err error
		if pr, err = loadPR(ctx, tx, prID); err != nil {
			return err
		}
		if st, err = loadSettings(ctx, tx); err != nil {
			return err
		}
		ps = loadPRSettings(ctx, tx)
		if pr.LatestScanID != "" {
			var raw []byte
			var c *string
			if err := tx.QueryRow(ctx, `SELECT pr_summary, conclusion FROM scans WHERE id=$1`, pr.LatestScanID).Scan(&raw, &c); err != nil {
				return err
			}
			_ = json.Unmarshal(raw, &sum)
			if c != nil {
				concl = *c
			}
			if err := lateFindings(ctx, tx, pr.LatestScanID, &sum); err != nil {
				return err
			}
		}
		if sum.Checks == nil {
			sum.Checks = map[string]string{}
		}
		if rv, err = loadReview(ctx, tx, pr.ID, pr.HeadSHA); err != nil {
			return err
		}
		if pr.ProjectID != "" {
			_ = tx.QueryRow(ctx, `SELECT COALESCE((SELECT comment_id FROM scans WHERE project_id=$1 AND pr_number=$2 AND comment_id IS NOT NULL
				ORDER BY created_at DESC LIMIT 1), 0)`, pr.ProjectID, pr.Number).Scan(&commentID)
			rows, err := tx.Query(ctx, `SELECT head_sha FROM scans WHERE project_id=$1 AND pr_number=$2 AND status='success'
				GROUP BY head_sha ORDER BY max(created_at) DESC LIMIT 10`, pr.ProjectID, pr.Number)
			if err != nil {
				return err
			}
			for rows.Next() {
				var s string
				if err := rows.Scan(&s); err == nil {
					commits = append(commits, s)
				}
			}
			rows.Close()
		}
		return nil
	})
	if err != nil {
		return err
	}

	rank := prrank.Rank(prrank.Input{Summary: sum, Review: rv, Open: pr.State == "open", OpenedAt: pr.OpenedAt, Now: time.Now()})
	if pr.LatestScanID == "" {
		rank.Level = prrank.Pending
	}
	fixedNow := rank.Level == prrank.Clean && (pr.Level == prrank.Critical || pr.Level == prrank.High || pr.Level == prrank.Medium)
	blocking := concl == "failure" || slices.ContainsFunc(rv.Findings, func(f render.ReviewFinding) bool {
		return f.Source == "rules" && f.Severity == "critical"
	})

	// Labels: dependency labels, review labels and the urgency.
	labelSet := map[string]bool{}
	for _, l := range append(slices.Clone(sum.Labels), rv.Labels...) {
		labelSet[l] = true
	}
	switch rank.Level {
	case prrank.Critical, prrank.High:
		labelSet["urgent"] = true
	}
	if blocking {
		labelSet["blocked"] = true
	}
	if rank.Level == prrank.Clean && pr.LatestScanID != "" {
		labelSet["clean"] = true
	}
	labels := make([]string, 0, len(labelSet))
	for l := range labelSet {
		labels = append(labels, l)
	}
	slices.Sort(labels)

	reasons, _ := json.Marshal(rank.Reasons)
	if err := withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE pull_requests SET urgency=$2, urgency_level=$3, reasons=$4, labels=$5, updated_at=now() WHERE id=$1`,
			pr.ID, rank.Score, rank.Level, reasons, labels)
		return err
	}); err != nil {
		return err
	}
	if gh == nil || pr.State != "open" || pr.LatestScanID == "" {
		return nil
	}
	owner, repo, _ := strings.Cut(pr.RepoFull, "/")

	// Comment.
	var reasonText []string
	for _, r := range rank.Reasons {
		reasonText = append(reasonText, render.Escape(r.Text))
	}
	body := render.PRComment(render.PRCommentInput{
		PublicURL: d.PublicURL, ProjectID: pr.ProjectID, PRNumber: pr.Number, Author: pr.Author, HeadSHA: pr.HeadSHA, Commits: commits,
		Summary: sum, Review: rv, Urgency: rank.Score, Level: rank.Level, Reasons: reasonText, FixedNow: fixedNow,
		BlockingNote: map[bool]string{true: "Block mode is on", false: ""}[st.BlockMode && blocking],
		Settings: render.CommentSettings{Sections: ps.Sections, MentionAuthor: ps.MentionAuthorOnBlock && blocking,
			Header: ps.Header, Footer: ps.Footer, PolicyNote: policyNote(st)},
	})
	quietClean := rank.Level == prrank.Clean && !fixedNow
	skipCreate := ps.CommentMode == "never" || (quietClean && (ps.CommentMode == "issues" || st.SuppressClean))
	if ps.CommentMode != "never" || commentID != 0 {
		id, err := d.upsertComment(ctx, gh, owner, repo, pr.Number, commentID, body, skipCreate)
		if err != nil {
			return fmt.Errorf("comment: %w", err)
		}
		if id != 0 && id != commentID {
			_ = withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE scans SET comment_id=$2 WHERE id=$1`, pr.LatestScanID, id)
				return err
			})
		}
	}
	_ = withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE scans SET report_md=$2 WHERE id=$1`, pr.LatestScanID, body)
		return err
	})

	// GitHub labels and the request-changes review are best effort (they need extra permissions).
	if ps.Labels.Enabled {
		if err := syncLabels(ctx, gh, owner, repo, pr.Number, ps.Labels.Prefix, labels); err != nil {
			d.Logger.Warn("pr labels", "pr", pr.RepoFull+"#"+fmt.Sprint(pr.Number), "err", err)
		}
	}
	if ps.RequestChangesOnBlock {
		if err := d.syncReview(ctx, gh, owner, repo, pr, blocking, rank); err != nil {
			d.Logger.Warn("pr review", "pr", pr.RepoFull+"#"+fmt.Sprint(pr.Number), "err", err)
		}
	}
	return nil
}

var labelColors = map[string]string{
	"blocked": "b60205", "urgent": "d93f0b", "malware": "b60205", "vulnerable": "d93f0b", "security": "d93f0b", "secrets": "b60205",
	"license-risk": "fbca04", "suspicious-package": "fbca04", "clean": "0e8a16", "dependencies": "0366d6",
}

// syncLabels makes the PR carry exactly our desired prefixed labels, leaving other labels alone.
func syncLabels(ctx context.Context, gh *github.Client, owner, repo string, number int, prefix string, want []string) error {
	desired := map[string]bool{}
	for _, l := range want {
		desired[prefix+l] = true
	}
	current, _, err := gh.Issues.ListLabelsByIssue(ctx, owner, repo, number, &github.ListOptions{PerPage: 100})
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, l := range current {
		n := l.GetName()
		have[n] = true
		if strings.HasPrefix(n, prefix) && !desired[n] {
			if _, err := gh.Issues.RemoveLabelForIssue(ctx, owner, repo, number, n); err != nil && !isNotFound(err) {
				return err
			}
		}
	}
	var add []string
	for n := range desired {
		if !have[n] {
			color := labelColors[strings.TrimPrefix(n, prefix)]
			if color == "" {
				color = "c5def5"
			}
			// Creating an existing label fails with 422; that's fine.
			_, _, _ = gh.Issues.CreateLabel(ctx, owner, repo, github.CreateIssueLabelRequest{Name: n, Color: github.Ptr(color),
				Description: github.Ptr("Added by depguard")})
			add = append(add, n)
		}
	}
	slices.Sort(add)
	if len(add) > 0 {
		_, _, err = gh.Issues.AddLabelsToIssue(ctx, owner, repo, number, add)
	}
	return err
}

// syncReview requests changes on a blocking head commit once, and dismisses
// our request when the PR is no longer blocking.
func (d Deps) syncReview(ctx context.Context, gh *github.Client, owner, repo string, pr prRow, blocking bool, rank prrank.Result) error {
	bot := d.GitHub.Slug + "[bot]"
	reviews, _, err := gh.PullRequests.ListReviews(ctx, owner, repo, pr.Number, &github.ListOptions{PerPage: 100})
	if err != nil {
		return err
	}
	var open []*github.PullRequestReview
	for _, r := range reviews {
		if r.GetUser().GetLogin() == bot && r.GetState() == "CHANGES_REQUESTED" {
			open = append(open, r)
		}
	}
	if !blocking {
		for _, r := range open {
			if _, _, err := gh.PullRequests.DismissReview(ctx, owner, repo, pr.Number, r.GetID(),
				github.PullRequestDismissReviewRequest{Message: "depguard: blocking issues are fixed."}); err != nil {
				return err
			}
		}
		return nil
	}
	for _, r := range open {
		if r.GetCommitID() == pr.HeadSHA {
			return nil // already requested for this commit
		}
	}
	var b strings.Builder
	b.WriteString("depguard found blocking issues in this pull request:\n\n")
	for _, r := range rank.Reasons {
		b.WriteString("- " + render.Escape(r.Text) + "\n")
	}
	b.WriteString("\nSee the depguard comment for fixes.")
	_, _, err = gh.PullRequests.CreateReview(ctx, owner, repo, pr.Number, &github.PullRequestReviewRequest{
		CommitID: github.Ptr(pr.HeadSHA), Event: github.Ptr("REQUEST_CHANGES"), Body: github.Ptr(b.String())})
	return err
}

// prFiles lists the PR's changed files with their patches (rules and AI review).
func prFiles(ctx context.Context, gh *github.Client, owner, repo string, number int) ([]prreview.File, error) {
	var out []prreview.File
	for f, err := range gh.PullRequests.ListFilesIter(ctx, owner, repo, number, &github.ListOptions{PerPage: 100}) {
		if err != nil {
			return nil, err
		}
		out = append(out, prreview.File{Path: f.GetFilename(), Status: f.GetStatus(), Patch: f.GetPatch(),
			Additions: f.GetAdditions(), Deletions: f.GetDeletions()})
		if len(out) == 3000 {
			break
		}
	}
	return out, nil
}

// storeRulesReview records the rule-based review of a head commit and whether
// the AI review is queued; returns the review.
func (d Deps) storeRulesReview(ctx context.Context, tenant, prID, scanID, head string, files []prreview.File, aiOn bool, aiNote string) (render.PRReview, error) {
	findings, reviewed := prreview.Review(files)
	labels := prreview.Labels(files, findings)
	rv := render.PRReview{Findings: findings, Labels: labels, Files: reviewed, AIStatus: "skipped", AINote: aiNote}
	if aiOn {
		rv.AIStatus, rv.AINote = "queued", ""
	}
	fj, _ := json.Marshal(findings)
	err := withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pr_reviews (id, tenant_id, pr_id, scan_id, head_sha, findings, labels, files_reviewed, ai_status, ai_note)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (pr_id, head_sha) DO UPDATE SET scan_id=EXCLUDED.scan_id,
			  findings=(SELECT COALESCE(jsonb_agg(f), '[]') FROM jsonb_array_elements(pr_reviews.findings) f WHERE f->>'source' = 'ai') || EXCLUDED.findings,
			  labels=EXCLUDED.labels, files_reviewed=EXCLUDED.files_reviewed,
			  ai_status=CASE WHEN pr_reviews.ai_status='done' THEN 'done' ELSE EXCLUDED.ai_status END,
			  ai_note=CASE WHEN pr_reviews.ai_status='done' THEN pr_reviews.ai_note ELSE EXCLUDED.ai_note END, updated_at=now()`,
			ids.New(), tenant, prID, scanID, head, fj, labels, reviewed, rv.AIStatus, rv.AINote)
		return err
	})
	return rv, err
}

// ---------------------------------------------------------------- workers

type aiReviewWorker struct {
	river.WorkerDefaults[jobs.ReviewPullRequest]
	d Deps
}

func (w *aiReviewWorker) Timeout(*river.Job[jobs.ReviewPullRequest]) time.Duration {
	return 10 * time.Minute
}

func (w *aiReviewWorker) Work(ctx context.Context, job *river.Job[jobs.ReviewPullRequest]) error {
	d, a := w.d, job.Args
	if d.Clients == nil {
		return river.JobCancel(errNoGitHub)
	}
	var pr prRow
	var ps prsettings.Settings
	var sum render.PRSummary
	err := withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
		var err error
		if pr, err = loadPR(ctx, tx, a.PRID); err != nil {
			return err
		}
		ps = loadPRSettings(ctx, tx)
		if pr.LatestScanID != "" {
			var raw []byte
			_ = tx.QueryRow(ctx, `SELECT pr_summary FROM scans WHERE id=$1`, pr.LatestScanID).Scan(&raw)
			_ = json.Unmarshal(raw, &sum)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if pr.HeadSHA != a.HeadSHA || pr.State != "open" {
		return nil // superseded or closed: the newer head gets its own review
	}
	gh, err := d.Clients.NewInstallationClient(a.InstallationID)
	if err != nil {
		return err
	}
	setStatus := func(status, note string) error {
		return withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE pr_reviews SET ai_status=$3, ai_note=$4, updated_at=now() WHERE pr_id=$1 AND head_sha=$2`, pr.ID, pr.HeadSHA, status, note)
			return err
		})
	}
	if !ps.AIReview.Enabled || !d.LLM.Enabled() {
		note := "turned off in Settings → Pull requests"
		if !d.LLM.Enabled() {
			note = "no AI model is configured on the server"
		}
		_ = setStatus("skipped", note)
		return d.refreshPR(ctx, gh, a.TenantID, pr.ID)
	}
	_ = setStatus("running", "")
	owner, repo, _ := strings.Cut(pr.RepoFull, "/")
	files, err := prFiles(ctx, gh, owner, repo, pr.Number)
	if err != nil {
		return err
	}
	ghPR, _, err := gh.PullRequests.Get(ctx, owner, repo, pr.Number)
	if err != nil {
		return err
	}
	var depSum []string
	for i, f := range sum.Fixes {
		if i == 5 {
			break
		}
		depSum = append(depSum, prrankPlain(f.Title))
	}
	res, err := aireview.Review(ctx, d.LLM, aireview.Request{Repo: pr.RepoFull, Title: ghPR.GetTitle(), Body: ghPR.GetBody(), Files: files,
		DepSummary: strings.Join(depSum, "; "), MaxBytes: ps.AIReview.MaxDiffKB << 10})
	if errors.Is(err, llm.ErrUnavailable) {
		next := d.LLM.NextRetry()
		note := "all AI models are rate limited"
		if !next.IsZero() {
			note += ", retrying " + next.UTC().Format("Jan 2 15:04 UTC")
		}
		_ = setStatus("rate_limited", note)
		_ = d.refreshPR(ctx, gh, a.TenantID, pr.ID)
		if job.Attempt >= 8 {
			return nil // give up quietly; the rule-based review stands
		}
		wait := time.Until(next)
		if next.IsZero() || wait < time.Minute {
			wait = 10 * time.Minute
		}
		return river.JobSnooze(min(wait, 12*time.Hour))
	}
	if err != nil {
		_ = setStatus("failed", firstTextLine(err.Error()))
		_ = d.refreshPR(ctx, gh, a.TenantID, pr.ID)
		return err // retried by River
	}
	fj, _ := json.Marshal(res.Findings)
	if err := withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE pr_reviews SET
			findings=(SELECT COALESCE(jsonb_agg(f), '[]') FROM jsonb_array_elements(findings) f WHERE f->>'source' <> 'ai') || $3::jsonb,
			labels=(SELECT array_agg(DISTINCT l ORDER BY l) FROM unnest(labels || $4::text[]) l),
			ai_status='done', ai_note='', ai_model=$5, ai_summary=$6, ai_risk=$7, truncated=$8,
			input_tokens=input_tokens+$9, output_tokens=output_tokens+$10, updated_at=now()
			WHERE pr_id=$1 AND head_sha=$2`, pr.ID, pr.HeadSHA, fj, res.Labels, res.Model, res.Summary, res.Risk, res.Truncated,
			res.InputTokens, res.OutputTokens)
		return err
	}); err != nil {
		return err
	}
	d.Logger.Info("ai review done", "pr", pr.RepoFull+"#"+fmt.Sprint(pr.Number), "model", res.Model, "findings", len(res.Findings),
		"tokens", res.InputTokens+res.OutputTokens)
	return d.refreshPR(ctx, gh, a.TenantID, pr.ID)
}

func prrankPlain(s string) string {
	return strings.NewReplacer("`", "", "**", "").Replace(s)
}

func firstTextLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	if len(l) > 200 {
		l = l[:200]
	}
	return l
}

type refreshWorker struct {
	river.WorkerDefaults[jobs.RefreshPullRequest]
	d Deps
}

func (w *refreshWorker) Work(ctx context.Context, job *river.Job[jobs.RefreshPullRequest]) error {
	var gh *github.Client
	if w.d.Clients != nil && job.Args.InstallationID != 0 {
		c, err := w.d.Clients.NewInstallationClient(job.Args.InstallationID)
		if err != nil {
			return err
		}
		gh = c
	}
	return w.d.refreshPR(ctx, gh, job.Args.TenantID, job.Args.PRID)
}

type prActionWorker struct {
	river.WorkerDefaults[jobs.PRAction]
	d Deps
}

func (w *prActionWorker) Work(ctx context.Context, job *river.Job[jobs.PRAction]) error {
	d, a := w.d, job.Args
	var kind, body, prID, actor string
	err := withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT kind, body, pr_id, actor_email FROM pr_activity WHERE id=$1 AND status='queued'`, a.ActivityID).
			Scan(&kind, &body, &prID, &actor)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // already done
	}
	if err != nil {
		return err
	}
	var pr prRow
	if err := withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
		var err error
		pr, err = loadPR(ctx, tx, prID)
		return err
	}); err != nil {
		return err
	}
	finish := func(ghID int64, err error) error {
		status, msg := "posted", ""
		if err != nil {
			status, msg = "failed", permissionHint(err)
		}
		_ = withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE pr_activity SET status=$2, gh_id=NULLIF($3,0), error=$4, updated_at=now() WHERE id=$1`, a.ActivityID, status, ghID, msg)
			return e
		})
		return nil // the result is recorded; no retries for user actions
	}
	if d.Clients == nil || pr.InstallationID == 0 {
		return finish(0, errors.New("GitHub is not connected for this repository"))
	}
	gh, err := d.Clients.NewInstallationClient(pr.InstallationID)
	if err != nil {
		return finish(0, err)
	}
	owner, repo, _ := strings.Cut(pr.RepoFull, "/")
	signature := "\n\n<sub>Posted from depguard by " + render.Escape(actor) + "</sub>"
	switch kind {
	case "comment":
		c, _, err := gh.Issues.CreateComment(ctx, owner, repo, pr.Number, github.IssueCommentRequest{Body: body + signature})
		return finish(c.GetID(), err)
	case "request_changes":
		r, _, err := gh.PullRequests.CreateReview(ctx, owner, repo, pr.Number, &github.PullRequestReviewRequest{
			CommitID: github.Ptr(pr.HeadSHA), Event: github.Ptr("REQUEST_CHANGES"), Body: github.Ptr(body + signature)})
		return finish(r.GetID(), err)
	case "rescan", "accept_risk":
		ghPR, _, err := gh.PullRequests.Get(ctx, owner, repo, pr.Number)
		if err == nil {
			err = d.enqueuePRScan(ctx, pr.InstallationID, pr.RepoID, pr.RepoFull, ghPR)
		}
		return finish(0, err)
	case "ai_review":
		_ = withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE pr_reviews SET ai_status='queued', ai_note='' WHERE pr_id=$1 AND head_sha=$2`, pr.ID, pr.HeadSHA)
			return err
		})
		err := d.enqueue(ctx, jobs.ReviewPullRequest{TenantID: a.TenantID, InstallationID: pr.InstallationID, PRID: pr.ID, HeadSHA: pr.HeadSHA},
			&river.InsertOpts{MaxAttempts: 10, UniqueOpts: river.UniqueOpts{ByArgs: true}})
		return finish(0, err)
	}
	return finish(0, fmt.Errorf("unknown action %q", kind))
}

// permissionHint turns a 403 into the GitHub App setting that fixes it.
func permissionHint(err error) string {
	var ge *github.ErrorResponse
	if errors.As(err, &ge) && ge.Response != nil && ge.Response.StatusCode == 403 {
		return "GitHub refused the action: grant the depguard GitHub App \"Pull requests: Read and write\" and accept the new permissions on the installation."
	}
	return firstTextLine(err.Error())
}

func (d Deps) enqueue(ctx context.Context, args river.JobArgs, opts *river.InsertOpts) error {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return err
	}
	_, err = client.Insert(ctx, args, opts)
	return err
}

// enqueuePRScan queues a scan of the PR's current head.
func (d Deps) enqueuePRScan(ctx context.Context, installationID int64, repoID int64, repoFull string, pr *github.PullRequest) error {
	return d.enqueue(ctx, jobs.ScanPullRequest{InstallationID: installationID, RepoID: repoID,
		RepoFullName: repoFull, PRNumber: pr.GetNumber(), BaseSHA: pr.GetBase().GetSHA(), HeadSHA: pr.GetHead().GetSHA(),
		BaseRef: pr.GetBase().GetRef(), HeadRef: pr.GetHead().GetRef(), IsDraft: pr.GetDraft()}, ghapp.JobOpts)
}
