package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/fixer"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/render"
	"github.com/depguard/depguard/internal/teamcfg"
	"github.com/google/go-github/v92/github"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

type fixPRWorker struct {
	river.WorkerDefaults[jobs.CreateFixPR]
	d Deps
}

func (w *fixPRWorker) Timeout(*river.Job[jobs.CreateFixPR]) time.Duration { return 10 * time.Minute }

type fixRow struct {
	projectID, eco, name, from, to, manifest string
	direct                                   bool
	installationID                           int64
	repoFull, defaultBranch                  string
}

func (w *fixPRWorker) Work(ctx context.Context, job *river.Job[jobs.CreateFixPR]) error {
	d, a := w.d, job.Args
	var f fixRow
	err := withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT fp.project_id, fp.ecosystem, fp.name, fp.from_version, fp.to_version, fp.manifest_path, fp.direct,
			COALESCE(r.installation_id, 0), COALESCE(r.full_name, ''), COALESCE(r.default_branch, '')
			FROM fix_prs fp JOIN projects p ON p.id = fp.project_id
			LEFT JOIN gh_repositories r ON r.id = p.gh_repo_id AND r.removed_at IS NULL
			WHERE fp.id = $1 AND fp.status = 'queued'`, a.FixID).
			Scan(&f.projectID, &f.eco, &f.name, &f.from, &f.to, &f.manifest, &f.direct, &f.installationID, &f.repoFull, &f.defaultBranch)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // already handled
	}
	if err != nil {
		return err
	}
	finish := func(status string, num int, url, branch string, cause error) error {
		msg := ""
		if cause != nil {
			msg = permissionHint(cause)
			if strings.Contains(msg, "Pull requests") || isForbidden(cause) {
				msg = "GitHub refused the change: grant the depguard GitHub App Contents: Read & write and Pull requests: Read & write, then accept it on the installation"
			}
		}
		return withTenant(ctx, d, a.TenantID, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE fix_prs SET status=$2, pr_number=NULLIF($3,0), pr_url=$4, branch=$5, error=$6, updated_at=now() WHERE id=$1`,
				a.FixID, status, num, url, branch, trunc(msg, 2000))
			return err
		})
	}
	if d.Clients == nil || f.installationID == 0 {
		return finish("failed", 0, "", "", errors.New("this project is not connected through the GitHub App"))
	}
	inputs := fixer.Inputs(f.eco, f.manifest)
	if inputs == nil {
		return finish("unsupported", 0, "", "", fmt.Errorf("automatic fixes are not supported for %s yet; run: %s",
			path.Base(f.manifest), render.UpgradeCommand(f.eco, f.name, f.to, f.manifest)))
	}
	gh, err := d.Clients.NewInstallationClient(f.installationID)
	if err != nil {
		return err
	}
	owner, repo, _ := strings.Cut(f.repoFull, "/")
	num, url, branch, err := d.openFixPR(ctx, gh, owner, repo, a.TenantID, f, inputs)
	switch {
	case errors.Is(err, fixer.ErrUnsupported), errors.Is(err, fixer.ErrNoChange):
		return finish("unsupported", 0, "", "", err)
	case err != nil:
		return finish("failed", 0, "", branch, err)
	}
	return finish("open", num, url, branch, nil)
}

func isForbidden(err error) bool {
	var er *github.ErrorResponse
	return errors.As(err, &er) && er.Response != nil && er.Response.StatusCode == http.StatusForbidden
}

var branchUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// openFixPR applies the upgrade to the default branch's files and opens (or
// reuses) the fix pull request.
func (d Deps) openFixPR(ctx context.Context, gh *github.Client, owner, repo, tenant string, f fixRow, inputs []string) (int, string, string, error) {
	br, _, err := gh.Repositories.GetBranch(ctx, owner, repo, f.defaultBranch, 1)
	if err != nil {
		return 0, "", "", fmt.Errorf("read %s: %w", f.defaultBranch, err)
	}
	sha := br.GetCommit().GetSHA()
	dir := path.Dir(f.manifest)
	var files []file
	for i, in := range inputs {
		p := path.Join(dir, in)
		b, err := fileAt(ctx, gh, owner, repo, p, sha, maxManifestBytes)
		if err != nil {
			return 0, "", "", fmt.Errorf("fetch %s: %w", p, err)
		}
		if b == nil && i == 0 {
			return 0, "", "", fmt.Errorf("%s not found on %s", p, f.defaultBranch)
		}
		if b != nil {
			files = append(files, file{Path: in, Data: b})
		}
	}
	tmp, err := os.MkdirTemp("", "depguard-fix-")
	if err != nil {
		return 0, "", "", err
	}
	defer os.RemoveAll(tmp)
	if _, notes := writeFiles(tmp, files); len(notes) > 0 {
		return 0, "", "", errors.New(strings.Join(notes, "; "))
	}
	changed, err := fixer.Apply(ctx, tmp, f.eco, f.manifest, f.name, f.to, f.direct)
	if err != nil {
		return 0, "", "", err
	}
	var entries []*github.TreeEntry
	for _, c := range changed {
		b, err := os.ReadFile(filepath.Join(tmp, c))
		if err != nil {
			return 0, "", "", err
		}
		entries = append(entries, &github.TreeEntry{Path: github.Ptr(path.Join(dir, c)), Mode: github.Ptr("100644"),
			Type: github.Ptr("blob"), Content: github.Ptr(string(b))})
	}
	tree, _, err := gh.Git.CreateTree(ctx, owner, repo, br.GetCommit().GetCommit().GetTree().GetSHA(), entries)
	if err != nil {
		return 0, "", "", fmt.Errorf("create tree: %w", err)
	}
	title := fmt.Sprintf("depguard: upgrade %s to %s", f.name, f.to)
	commit, _, err := gh.Git.CreateCommit(ctx, owner, repo, github.Commit{Message: github.Ptr(title + "\n\nFixes known vulnerabilities in " + f.name + " " + f.from + "."),
		Tree: tree, Parents: []*github.Commit{{SHA: github.Ptr(sha)}}}, nil)
	if err != nil {
		return 0, "", "", fmt.Errorf("create commit: %w", err)
	}
	branch := "depguard/fix-" + strings.Trim(branchUnsafe.ReplaceAllString(f.name, "-"), "-.") + "-" + branchUnsafe.ReplaceAllString(f.to, "-")
	if dir != "." {
		branch += "-" + strings.Trim(branchUnsafe.ReplaceAllString(dir, "-"), "-.")
	}
	if _, _, err := gh.Git.CreateRef(ctx, owner, repo, github.CreateRef{Ref: "refs/heads/" + branch, SHA: commit.GetSHA()}); err != nil {
		// The branch exists from an earlier attempt: point it at the new commit.
		if _, _, err2 := gh.Git.UpdateRef(ctx, owner, repo, "heads/"+branch, github.UpdateRef{SHA: commit.GetSHA(), Force: github.Ptr(true)}); err2 != nil {
			return 0, "", branch, fmt.Errorf("create branch: %w", err)
		}
	}
	advs := d.fixAdvisories(ctx, tenant, f)
	body := render.FixPRBody(f.eco, f.name, f.from, f.to, f.manifest, f.direct, advs, strings.TrimRight(d.PublicURL, "/")+"/projects/"+f.projectID)
	pr, _, err := gh.PullRequests.Create(ctx, owner, repo, github.CreatePullRequest{Title: github.Ptr(title), Head: branch,
		Base: f.defaultBranch, Body: github.Ptr(body)})
	if err != nil {
		// Reuse the open PR of this branch.
		prs, _, lerr := gh.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{Head: owner + ":" + branch, State: "open"})
		if lerr == nil && len(prs) > 0 {
			return prs[0].GetNumber(), prs[0].GetHTMLURL(), branch, nil
		}
		return 0, "", branch, fmt.Errorf("open pull request: %w", err)
	}
	return pr.GetNumber(), pr.GetHTMLURL(), branch, nil
}

// fixAdvisories lists the advisories of the package version being replaced.
func (d Deps) fixAdvisories(ctx context.Context, tenant string, f fixRow) []render.FixAdvisory {
	var out []render.FixAdvisory
	_ = withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT cv.advisory_id, cv.risk FROM component_vulnerabilities cv JOIN components c ON c.id = cv.component_id
			WHERE c.ecosystem=$1 AND c.name=$2 AND c.version=$3 AND cv.advisory_id NOT LIKE 'MAL-%'
			ORDER BY array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW'], cv.risk), cv.advisory_id`, f.eco, f.name, f.from)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a render.FixAdvisory
			if rows.Scan(&a.ID, &a.Risk) == nil {
				out = append(out, a)
			}
		}
		return rows.Err()
	})
	return out
}

// FixCandidate is a vulnerable package of a project version with a known fix.
type FixCandidate struct {
	Ecosystem, Name, Version, FixedIn, Manifest string
	Direct, KEV                                 bool
	Risk                                        string // highest
	Advisories                                  []string
}

// FixCandidates lists current vulnerable packages of a version that have a
// fixed version, one row per package and manifest, fix = highest fixed_in.
func FixCandidates(ctx context.Context, tx pgx.Tx, versionID string) ([]FixCandidate, error) {
	rows, err := tx.Query(ctx, `WITH vul AS (SELECT c.ecosystem, c.name, c.version, pvc.manifest_path, pvc.direct, cv.advisory_id, cv.risk, COALESCE(cv.fixed_in,'') AS fixed
		  FROM project_version_components pvc JOIN components c ON c.id = pvc.component_id
		  JOIN component_vulnerabilities cv ON cv.component_id = c.id
		  WHERE pvc.project_version_id = $1 AND cv.advisory_id NOT LIKE 'MAL-%'),
		kev AS (SELECT DISTINCT v.advisory_id FROM (SELECT DISTINCT advisory_id FROM vul) v
		  WHERE EXISTS (SELECT 1 FROM cve_score cs WHERE cs.kev AND (cs.cve = v.advisory_id OR cs.cve IN (SELECT alias FROM advisory_alias WHERE advisory_id = v.advisory_id))))
		SELECT vul.ecosystem, vul.name, vul.version, vul.manifest_path, vul.direct, vul.advisory_id, vul.risk, vul.fixed, kev.advisory_id IS NOT NULL
		FROM vul LEFT JOIN kev ON kev.advisory_id = vul.advisory_id`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byKey := map[string]*FixCandidate{}
	var order []string
	rank := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
	for rows.Next() {
		var c FixCandidate
		var adv, risk, fixed string
		var kev bool
		if err := rows.Scan(&c.Ecosystem, &c.Name, &c.Version, &c.Manifest, &c.Direct, &adv, &risk, &fixed, &kev); err != nil {
			return nil, err
		}
		k := c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version + "\x00" + c.Manifest
		cur := byKey[k]
		if cur == nil {
			cur = &c
			byKey[k] = cur
			order = append(order, k)
		}
		cur.Advisories = append(cur.Advisories, adv)
		cur.KEV = cur.KEV || kev
		if rank[risk] > rank[cur.Risk] {
			cur.Risk = risk
		}
		if fixed == "" {
			continue
		}
		if cur.FixedIn == "" {
			cur.FixedIn = fixed
		} else if cmp, err := enrich.CompareVersions(enrich.OSVEcosystemName(c.Ecosystem), fixed, cur.FixedIn); err == nil && cmp > 0 {
			cur.FixedIn = fixed
		}
	}
	out := make([]FixCandidate, 0, len(order))
	for _, k := range order {
		if c := byKey[k]; c.FixedIn != "" {
			out = append(out, *c)
		}
	}
	return out, rows.Err()
}

// autoFix queues fix PRs after a default-branch scan when the team enabled it.
func (d Deps) autoFix(ctx context.Context, tenant, projectID, versionID, branch string) {
	err := withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		var raw []byte
		var defaultBranch string
		if err := tx.QueryRow(ctx, `SELECT ts.fix_settings, COALESCE(r.default_branch,'') FROM tenant_settings ts, projects p
			LEFT JOIN gh_repositories r ON r.id = p.gh_repo_id WHERE p.id=$1`, projectID).Scan(&raw, &defaultBranch); err != nil {
			return err
		}
		cfg := teamcfg.ParseFix(raw)
		if !cfg.Auto || defaultBranch == "" || branch != defaultBranch {
			return nil
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM fix_prs WHERE project_id=$1 AND status IN ('queued','open')`, projectID).Scan(&open); err != nil {
			return err
		}
		cands, err := FixCandidates(ctx, tx, versionID)
		if err != nil {
			return err
		}
		for _, c := range cands {
			if open >= cfg.MaxOpen {
				break
			}
			if fixer.Inputs(c.Ecosystem, c.Manifest) == nil || !(c.KEV && cfg.KEV || slices.Contains(cfg.Levels, strings.ToLower(c.Risk))) {
				continue
			}
			id := ids.New()
			tag, err := tx.Exec(ctx, `INSERT INTO fix_prs (id, tenant_id, project_id, ecosystem, name, from_version, to_version, manifest_path, direct, advisories, trigger, created_by)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'auto','depguard') ON CONFLICT DO NOTHING`,
				id, tenant, projectID, c.Ecosystem, c.Name, c.Version, c.FixedIn, c.Manifest, c.Direct, c.Advisories)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				continue
			}
			client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
			if err != nil {
				return err
			}
			if _, err := client.InsertTx(ctx, tx, jobs.CreateFixPR{TenantID: tenant, FixID: id}, &river.InsertOpts{MaxAttempts: 3}); err != nil {
				return err
			}
			open++
		}
		return nil
	})
	if err != nil {
		d.Logger.Warn("auto-fix", "project", projectID, "err", err)
	}
}
