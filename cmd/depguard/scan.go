package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"mime/multipart"
	"net/textproto"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Lockfile names vet can parse (vet/pkg/parser + osv-scanner lockfile parsers).
var lockfileNames = map[string]bool{
	"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "bun.lock": true,
	"requirements.txt": true, "Pipfile.lock": true, "poetry.lock": true, "uv.lock": true, "pdm.lock": true,
	"go.mod": true, "pom.xml": true, "gradle.lockfile": true, "buildscript-gradle.lockfile": true,
	"Cargo.lock": true, "Gemfile.lock": true, "composer.lock": true, "pubspec.lock": true, "mix.lock": true,
	"packages.lock.json": true, "conan.lock": true, "renv.lock": true, ".terraform.lock.hcl": true,
}

var skipDirs = map[string]bool{"node_modules": true, "vendor": true, ".git": true, ".venv": true, "venv": true,
	"__pycache__": true, ".tox": true, "target": true, "dist": true, "build": true}

var workflowRe = regexp.MustCompile(`(^|/)\.github/(workflows|actions)/.*\.ya?ml$`)

const (
	maxFiles     = 50
	maxFileBytes = 10 << 20
	maxTotal     = 50 << 20
)

// findLockfiles returns repo-relative (slash) paths of supported lockfiles under root.
func findLockfiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || (strings.HasPrefix(d.Name(), ".") && d.Name() != ".github")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks
		}
		if lockfileNames[d.Name()] || workflowRe.MatchString(rel) {
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

type scanResult struct {
	ScanID     string  `json:"scan_id"`
	Status     string  `json:"status"`
	Conclusion *string `json:"conclusion"`
	ReportMD   *string `json:"report_md"`
	URL        string  `json:"url"`
}

func runScan(args []string) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	apiURL, apiKey := addClientFlags(fs)
	project := fs.String("project", "", "project name (default: CI repository or directory name)")
	ver := fs.String("version", "", "version/branch (default: CI branch or git branch)")
	source := fs.String("source", "", "cli|gitlab|bitbucket|github (default: detected from CI env)")
	dir := fs.String("dir", ".", "directory to search for lockfiles")
	failOn := fs.Bool("fail-on-violation", false, "exit 1 when the scan conclusion is failure")
	format := fs.String("format", "md", "output format: md|json")
	timeout := fs.Duration("timeout", 10*time.Minute, "maximum time to wait for the scan")
	fs.Parse(args)
	if *format != "md" && *format != "json" {
		return 0, errors.New("--format must be md or json")
	}
	c, err := newClient(*apiURL, *apiKey)
	if err != nil {
		return 0, err
	}
	root, err := filepath.Abs(*dir)
	if err != nil {
		return 0, err
	}
	src, proj, branch := detectCI(root)
	if *source == "" {
		*source = src
	}
	if *project == "" {
		*project = proj
	}
	if *ver == "" {
		*ver = branch
	}
	files, err := findLockfiles(root)
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		return 0, fmt.Errorf("no supported lockfiles found under %s", root)
	}
	body, ctype, n, err := buildUpload(root, files, map[string]string{"project": *project, "version": *ver, "source": *source})
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(os.Stderr, "depguard: scanning %d lockfile(s) for %s@%s\n", n, *project, *ver)

	var res scanResult
	if _, err := c.do("POST", "/v1/scans?wait=true", ctype, body, &res); err != nil {
		return 0, err
	}
	deadline := time.Now().Add(*timeout)
	for (res.Status == "queued" || res.Status == "running") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		if _, err := c.do("GET", "/v1/scans/"+res.ScanID, "", nil, &res); err != nil {
			return 0, err
		}
	}
	if *format == "json" {
		j, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(j))
	} else {
		if res.ReportMD != nil && *res.ReportMD != "" {
			fmt.Println(*res.ReportMD)
		}
		fmt.Printf("\nScan %s: status=%s conclusion=%s\n%s\n", res.ScanID, res.Status, deref(res.Conclusion), res.URL)
	}
	switch {
	case res.Status == "queued" || res.Status == "running":
		return 0, fmt.Errorf("scan %s did not finish within %s", res.ScanID, *timeout)
	case res.Status == "failed":
		return 0, fmt.Errorf("scan %s failed", res.ScanID)
	case *failOn && deref(res.Conclusion) == "failure":
		return 1, nil
	}
	return 0, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// buildUpload creates the multipart body, applying the server's size caps.
func buildUpload(root string, files []string, fields map[string]string) (*bytes.Buffer, string, int, error) {
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	n, total := 0, 0
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			return nil, "", 0, err
		}
		if len(b) > maxFileBytes {
			fmt.Fprintf(os.Stderr, "depguard: skipping %s (larger than 10 MB)\n", f)
			continue
		}
		if n == maxFiles || total+len(b) > maxTotal {
			fmt.Fprintf(os.Stderr, "depguard: upload limit reached (50 files / 50 MB); skipping %s and later files\n", f)
			break
		}
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="lockfile"; filename=%q`, f))
		h.Set("Content-Type", "application/octet-stream")
		w, err := mw.CreatePart(h)
		if err != nil {
			return nil, "", 0, err
		}
		w.Write(b)
		n, total = n+1, total+len(b)
	}
	return buf, mw.FormDataContentType(), n, mw.Close()
}

// detectCI derives source, project and branch from CI env vars, then git.
func detectCI(root string) (source, project, branch string) {
	switch {
	case os.Getenv("GITHUB_ACTIONS") == "true":
		source, project = "github", os.Getenv("GITHUB_REPOSITORY")
		branch = firstNonEmpty(os.Getenv("GITHUB_HEAD_REF"), os.Getenv("GITHUB_REF_NAME"))
	case os.Getenv("GITLAB_CI") != "":
		source, project = "gitlab", os.Getenv("CI_PROJECT_PATH")
		branch = firstNonEmpty(os.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"), os.Getenv("CI_COMMIT_REF_NAME"))
	case os.Getenv("BITBUCKET_BUILD_NUMBER") != "":
		source, project, branch = "bitbucket", os.Getenv("BITBUCKET_REPO_FULL_NAME"), os.Getenv("BITBUCKET_BRANCH")
	default:
		source = "cli"
	}
	if project == "" {
		project = path.Base(filepath.ToSlash(root))
	}
	if branch == "" {
		if out, err := exec.Command("git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD").Output(); err == nil {
			branch = strings.TrimSpace(string(out))
		}
	}
	if branch == "" || branch == "HEAD" {
		branch = "main"
	}
	return
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
