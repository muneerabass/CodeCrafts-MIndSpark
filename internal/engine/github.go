package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/render"
	"github.com/depguard/depguard/internal/scan"
	"github.com/google/go-github/v92/github"
)

var errTooLarge = errors.New("file exceeds size limit")

// fetchBlob downloads a git blob as raw bytes, reading at most limit bytes.
func fetchBlob(ctx context.Context, gh *github.Client, owner, repo, sha string, limit int64) ([]byte, error) {
	req, err := gh.NewRequest(ctx, http.MethodGet, fmt.Sprintf("repos/%s/%s/git/blobs/%s",
		url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(sha)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.raw")
	resp, err := gh.BareDo(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errTooLarge
	}
	return b, nil
}

func isNotFound(err error) bool {
	var er *github.ErrorResponse
	return errors.As(err, &er) && er.Response != nil && er.Response.StatusCode == http.StatusNotFound
}

// fileAt fetches a file's content at ref; nil, nil when it does not exist.
func fileAt(ctx context.Context, gh *github.Client, owner, repo, p, ref string, limit int64) ([]byte, error) {
	fc, _, _, err := gh.Repositories.GetContents(ctx, owner, repo, p, &github.RepositoryContentGetOptions{Ref: ref})
	if isNotFound(err) || (err == nil && fc == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if int64(fc.GetSize()) > limit {
		return nil, errTooLarge
	}
	return fetchBlob(ctx, gh, owner, repo, fc.GetSHA(), limit)
}

// prFile is a file changed by a PR.
type prFile struct {
	Path, PrevPath, Status, SHA string // SHA = head blob
}

// prFileCap is GitHub's limit on the PR files API.
const prFileCap = 3000

// changedFiles lists PR files, and returns the merge base used as the diff
// base. Past the files-API cap it diffs the merge-base and head trees.
func changedFiles(ctx context.Context, gh *github.Client, owner, repo string, pr int, baseSHA, headSHA string) ([]prFile, string, error) {
	mergeBase := baseSHA
	if cmp, _, err := gh.Repositories.CompareCommits(ctx, owner, repo, baseSHA, headSHA, &github.ListOptions{PerPage: 1}); err == nil &&
		cmp.GetMergeBaseCommit().GetSHA() != "" {
		mergeBase = cmp.GetMergeBaseCommit().GetSHA()
	}
	var files []prFile
	for f, err := range gh.PullRequests.ListFilesIter(ctx, owner, repo, pr, &github.ListOptions{PerPage: 100}) {
		if err != nil {
			return nil, "", err
		}
		files = append(files, prFile{Path: f.GetFilename(), PrevPath: f.GetPreviousFilename(), Status: f.GetStatus(), SHA: f.GetSHA()})
	}
	if len(files) < prFileCap {
		return files, mergeBase, nil
	}
	base, err := treeBlobs(ctx, gh, owner, repo, mergeBase)
	if err != nil {
		return nil, "", err
	}
	head, err := treeBlobs(ctx, gh, owner, repo, headSHA)
	if err != nil {
		return nil, "", err
	}
	files = files[:0]
	for p, e := range head {
		switch b, ok := base[p]; {
		case !ok:
			files = append(files, prFile{Path: p, Status: "added", SHA: e.GetSHA()})
		case b.GetSHA() != e.GetSHA():
			files = append(files, prFile{Path: p, Status: "modified", SHA: e.GetSHA()})
		}
	}
	for p := range base {
		if _, ok := head[p]; !ok {
			files = append(files, prFile{Path: p, Status: "removed"})
		}
	}
	slices.SortFunc(files, func(a, b prFile) int { return strings.Compare(a.Path, b.Path) })
	return files, mergeBase, nil
}

// treeBlobs lists all blobs of a commit's tree.
func treeBlobs(ctx context.Context, gh *github.Client, owner, repo, sha string) (map[string]*github.TreeEntry, error) {
	t, _, err := gh.Git.GetTree(ctx, owner, repo, sha, true)
	if err != nil {
		return nil, err
	}
	out := map[string]*github.TreeEntry{}
	for _, e := range t.Entries {
		if e.GetType() == "blob" {
			out[e.GetPath()] = e
		}
	}
	return out, nil
}

var skipDirs = map[string]bool{"node_modules": true, "vendor": true, "testdata": true, "fixtures": true, "test-fixtures": true}

// fullScanManifests picks lockfiles from a tree: not in vendored/test dirs,
// within size limit, shallowest first, at most maxManifests.
func fullScanManifests(blobs map[string]*github.TreeEntry) []*github.TreeEntry {
	var out []*github.TreeEntry
	for p, e := range blobs {
		if !scan.IsManifest(p) || e.GetSize() > maxManifestBytes || slices.ContainsFunc(strings.Split(p, "/"), func(s string) bool { return skipDirs[s] }) {
			continue
		}
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b *github.TreeEntry) int {
		if x := strings.Count(a.GetPath(), "/") - strings.Count(b.GetPath(), "/"); x != 0 {
			return x
		}
		return strings.Compare(a.GetPath(), b.GetPath())
	})
	return out[:min(len(out), maxManifests)]
}

var sourceExts = map[string]bool{".py": true, ".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true, ".java": true, ".go": true}

// sourceFiles fetches changed source files for xbom within size budgets.
func sourceFiles(ctx context.Context, gh *github.Client, owner, repo string, files []prFile) []file {
	var out []file
	total := 0
	for _, f := range files {
		if f.Status == "removed" || f.SHA == "" || !sourceExts[path.Ext(f.Path)] || total >= maxSourceTotal {
			continue
		}
		b, err := fetchBlob(ctx, gh, owner, repo, f.SHA, maxSourceBytes)
		if err != nil || total+len(b) > maxSourceTotal {
			continue
		}
		total += len(b)
		out = append(out, file{Path: f.Path, Data: b})
	}
	return out
}

func (d Deps) scanURL(scanID string) string {
	return strings.TrimRight(d.PublicURL, "/") + "/scans/" + scanID
}

func (d Deps) createCheckRun(ctx context.Context, gh *github.Client, owner, repo, headSHA, scanID string) (int64, error) {
	cr, _, err := gh.Checks.CreateCheckRun(ctx, owner, repo, github.CreateCheckRunOptions{
		Name:       d.GitHub.CheckRunName,
		HeadSHA:    headSHA,
		Status:     github.Ptr("in_progress"),
		ExternalID: github.Ptr(scanID),
		DetailsURL: github.Ptr(d.scanURL(scanID)),
		StartedAt:  &github.Timestamp{Time: time.Now()},
		Output:     &github.CheckRunOutput{Title: github.Ptr("Scanning dependency changes"), Summary: github.Ptr("depguard is scanning this pull request.")},
	})
	return cr.GetID(), err
}

// completeCheckRun sets the conclusion; annotations go in batches of 50.
func (d Deps) completeCheckRun(ctx context.Context, gh *github.Client, owner, repo string, id int64, concl, title, summary string, anns []render.Annotation) error {
	batch := func(a []render.Annotation) []*github.CheckRunAnnotation {
		var out []*github.CheckRunAnnotation
		for _, x := range a {
			out = append(out, &github.CheckRunAnnotation{Path: github.Ptr(x.Path), StartLine: github.Ptr(1), EndLine: github.Ptr(1),
				AnnotationLevel: github.Ptr(x.Level), Title: github.Ptr(trunc(x.Title, 255)), Message: github.Ptr(trunc(x.Message, 64000))})
		}
		return out
	}
	first := anns[:min(len(anns), 50)]
	_, _, err := gh.Checks.UpdateCheckRun(ctx, owner, repo, id, github.UpdateCheckRunOptions{
		Name:        d.GitHub.CheckRunName,
		Status:      github.Ptr("completed"),
		Conclusion:  github.Ptr(concl),
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output:      &github.CheckRunOutput{Title: github.Ptr(title), Summary: github.Ptr(summary), Annotations: batch(first)},
	})
	for rest := anns[len(first):]; err == nil && len(rest) > 0; rest = rest[min(len(rest), 50):] {
		_, _, err = gh.Checks.UpdateCheckRun(ctx, owner, repo, id, github.UpdateCheckRunOptions{
			Name:   d.GitHub.CheckRunName,
			Output: &github.CheckRunOutput{Title: github.Ptr(title), Summary: github.Ptr(summary), Annotations: batch(rest[:min(len(rest), 50)])},
		})
	}
	return err
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// findOwnComment finds our sticky comment by marker among the app's comments.
func (d Deps) findOwnComment(ctx context.Context, gh *github.Client, owner, repo string, pr int) (int64, error) {
	for c, err := range gh.Issues.ListCommentsIter(ctx, owner, repo, pr, &github.IssueListCommentsOptions{ListOptions: github.ListOptions{PerPage: 100}}) {
		if err != nil {
			return 0, err
		}
		u := c.GetUser()
		ours := u.GetType() == "Bot" && (d.GitHub.Slug == "" || u.GetLogin() == d.GitHub.Slug+"[bot]")
		if ours && strings.Contains(c.GetBody(), render.Marker) {
			return c.GetID(), nil
		}
	}
	return 0, nil
}

// upsertComment edits the sticky comment (known id or found by marker), or
// creates it unless skipCreate. Returns the comment id (0 if none).
func (d Deps) upsertComment(ctx context.Context, gh *github.Client, owner, repo string, pr int, knownID int64, body string, skipCreate bool) (int64, error) {
	id := knownID
	if id == 0 {
		var err error
		if id, err = d.findOwnComment(ctx, gh, owner, repo, pr); err != nil {
			return 0, err
		}
	}
	if id != 0 {
		_, _, err := gh.Issues.UpdateComment(ctx, owner, repo, id, github.IssueCommentRequest{Body: body})
		if err == nil {
			return id, nil
		}
		if !isNotFound(err) {
			return 0, err
		}
		if knownID != 0 { // stored comment was deleted; look for another by marker
			return d.upsertComment(ctx, gh, owner, repo, pr, 0, body, skipCreate)
		}
	}
	if skipCreate {
		return 0, nil
	}
	c, _, err := gh.Issues.CreateComment(ctx, owner, repo, pr, github.IssueCommentRequest{Body: body})
	return c.GetID(), err
}
