// Package fixer upgrades one package in a copy of a repository's manifest and
// lockfile, so the worker can open a fix pull request. Package managers run in
// lockfile-only mode with install scripts disabled and a scrubbed environment.
package fixer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ErrUnsupported means the lockfile type cannot be updated automatically.
var ErrUnsupported = errors.New("automatic fix is not supported for this lockfile")

// ErrNoChange means the update left the files unchanged (usually a transitive
// dependency whose parent pins the vulnerable range).
var ErrNoChange = errors.New("the update did not change the lockfile; upgrade the parent dependency")

// Inputs lists the repo files (relative to the manifest's directory) that a fix
// of this lockfile reads and may rewrite; nil means unsupported.
func Inputs(eco, lockfile string) []string {
	switch kind(eco, lockfile) {
	case "npm":
		return []string{"package.json", "package-lock.json"}
	case "pnpm":
		return []string{"package.json", "pnpm-lock.yaml"}
	case "go":
		return []string{"go.mod", "go.sum"}
	case "pip":
		return []string{path.Base(lockfile)}
	}
	return nil
}

func kind(eco, lockfile string) string {
	base := path.Base(lockfile)
	switch strings.ToLower(eco) {
	case "npm":
		switch base {
		case "package-lock.json", "package.json":
			return "npm"
		case "pnpm-lock.yaml":
			return "pnpm"
		}
	case "go":
		if base == "go.mod" || base == "go.sum" {
			return "go"
		}
	case "pypi":
		if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
			return "pip"
		}
	}
	return ""
}

// Apply upgrades name to version in dir (holding the files from Inputs) and
// returns the files that changed. direct tells npm/pnpm whether to add the
// package to package.json or only refresh the lockfile.
func Apply(ctx context.Context, dir, eco, lockfile, name, version string, direct bool) ([]string, error) {
	k := kind(eco, lockfile)
	if k == "" {
		return nil, ErrUnsupported
	}
	files := Inputs(eco, lockfile)
	before := snapshot(dir, files)
	var err error
	switch k {
	case "npm":
		if direct {
			err = run(ctx, dir, "npm", "install", name+"@"+version, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund")
		} else {
			err = run(ctx, dir, "npm", "update", name, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund")
		}
	case "pnpm":
		if direct {
			err = run(ctx, dir, "pnpm", "add", name+"@"+version, "--lockfile-only", "--ignore-scripts")
		} else {
			err = run(ctx, dir, "pnpm", "update", name, "--lockfile-only", "--ignore-scripts")
		}
	case "go":
		v := version
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		if err = run(ctx, dir, "go", "get", name+"@"+v); err == nil {
			err = run(ctx, dir, "go", "mod", "tidy")
		}
	case "pip":
		err = pinRequirement(filepath.Join(dir, files[0]), name, version)
	}
	if err != nil {
		return nil, err
	}
	var changed []string
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if b != nil && !bytes.Equal(b, before[f]) {
			changed = append(changed, f)
		}
	}
	if len(changed) == 0 {
		return nil, ErrNoChange
	}
	return changed, nil
}

func snapshot(dir string, files []string) map[string][]byte {
	m := map[string][]byte{}
	for _, f := range files {
		m[f], _ = os.ReadFile(filepath.Join(dir, f))
	}
	return m
}

// run executes a package manager with only PATH and a throwaway HOME: the
// worker's own environment (API keys, database URL) never reaches it.
func run(ctx context.Context, dir, bin string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	home, err := os.MkdirTemp("", "depguard-fix-home-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(home)
	cache := cacheDir()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "npm_config_cache=" + filepath.Join(cache, "npm"),
		// GOTOOLCHAIN=auto fetches the Go version a go.mod asks for (verified by the checksum
		// database); module and toolchain downloads persist in the cache between fixes.
		"GOPATH=" + filepath.Join(home, "go"), "GOMODCACHE=" + filepath.Join(cache, "gomod"), "GOCACHE=" + filepath.Join(cache, "gobuild"),
		"GOTOOLCHAIN=auto", "GOFLAGS=-mod=mod -modcacherw", "GOSUMDB=sum.golang.org", "GOPROXY=https://proxy.golang.org,direct", // distro Go builds may disable both
		"CI=1",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, tail(string(out), 600))
	}
	return nil
}

// cacheDir holds package-manager downloads shared by fixes (never credentials).
func cacheDir() string {
	if d := os.Getenv("DEPGUARD_FIX_CACHE"); d != "" {
		return d
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "depguard-fix")
	}
	return filepath.Join(os.TempDir(), "depguard-fix-cache")
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// pinRequirement rewrites the requirement line for name to name==version,
// keeping extras, environment markers and comments.
func pinRequirement(file, name, version string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	norm := func(s string) string { return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(s, "-")) }
	re := regexp.MustCompile(`^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*([=<>!~][^;#]*)?(.*)$`)
	lines := strings.Split(string(b), "\n")
	found := false
	for i, l := range lines {
		m := re.FindStringSubmatch(l)
		if m == nil || norm(m[2]) != norm(name) || strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		rest := strings.TrimLeft(m[5], " ")
		if rest != "" {
			rest = " " + rest
		}
		lines[i] = m[1] + m[2] + m[3] + "==" + version + rest
		found = true
	}
	if !found {
		return ErrNoChange
	}
	return os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0o600)
}
