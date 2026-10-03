package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Wire types for POST /v1/packages/check.
type checkFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type checkPkg struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Direct    *bool  `json:"direct,omitempty"`
}

type checkRequest struct {
	Packages  []checkPkg  `json:"packages,omitempty"`
	Before    []checkFile `json:"before,omitempty"`
	After     []checkFile `json:"after,omitempty"`
	Manifests []checkFile `json:"manifests,omitempty"`
	RepoRules []rule      `json:"repo_rules,omitempty"`
}

// resolution is what an install would bring in, worked out without installing.
type resolution struct {
	req     checkRequest
	note    string // shown to the user, e.g. "approximate: resolved with npm"
	partial bool   // only the packages named on the command line could be checked
	key     string // cache key: unchanged resolved lockfile = already checked
}

const resolveTimeout = 5 * time.Minute

// resolve works out the packages an install would add, in a temporary copy of
// the project with install scripts disabled. bin is the real tool.
func resolve(inv invocation, dir, bin string) (*resolution, error) {
	switch inv.tool {
	case "npm", "pnpm", "yarn":
		return resolveJS(inv, dir, bin)
	case "pip":
		return resolvePip(inv, bin)
	case "uv":
		return resolveUV(inv, dir, bin)
	case "poetry":
		return resolvePoetry(inv, dir, bin)
	case "go":
		return resolveGo(inv, dir, bin)
	case "cargo":
		return resolveCargo(inv, dir, bin)
	}
	return nil, fmt.Errorf("unsupported tool %s", inv.tool)
}

// ---------------------------------------------------------------- JavaScript

func resolveJS(inv invocation, dir, bin string) (*resolution, error) {
	root := dir
	if !inv.global {
		if r := findUp(dir, "package.json"); r != "" {
			root = r
		}
	}
	lockName := map[string]string{"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "yarn": "yarn.lock"}[inv.tool]
	if inv.tool == "npm" && exists(filepath.Join(root, "npm-shrinkwrap.json")) {
		lockName = "npm-shrinkwrap.json"
	}
	lock := filepath.Join(root, lockName)
	whole := len(inv.specs) == 0 && !inv.global
	// A frozen install (npm ci, yarn/pnpm install with a lockfile) installs exactly the lockfile.
	if whole && exists(lock) && (inv.sub == "ci" || inv.sub == "clean-install" || inv.tool == "yarn" || inv.tool == "pnpm") {
		return lockfileOnly(root, lockName, "package.json")
	}
	if inv.tool == "yarn" {
		// Yarn cannot update only the lockfile (classic); resolve the same request with npm.
		npm, err := exec.LookPath("npm")
		if err != nil {
			return nil, errors.New("yarn add is checked by resolving with npm, which was not found")
		}
		r, err := npmResolve(root, npm, append([]string{"install"}, jsInstallArgs(inv)...), "package-lock.json", inv.global)
		if r != nil {
			r.note, r.req.Before = "approximate: resolved with npm", nil
		}
		return r, err
	}
	sub := inv.args
	if inv.global {
		sub = append([]string{"install"}, jsInstallArgs(inv)...)
	}
	return npmResolve(root, bin, sub, lockName, inv.global)
}

// jsInstallArgs drops the subcommand and global flags.
func jsInstallArgs(inv invocation) []string {
	var out []string
	skipped := false
	for _, a := range inv.args {
		if !skipped && a == inv.sub {
			skipped = true
			continue
		}
		if a == "-g" || a == "--global" || a == "--location=global" {
			continue
		}
		out = append(out, a)
	}
	return out
}

func npmResolve(root, bin string, args []string, lockName string, global bool) (*resolution, error) {
	tmp, err := os.MkdirTemp("", "depguard-js-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if global {
		if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"depguard-global","version":"0.0.0"}`), 0o600); err != nil {
			return nil, err
		}
	} else if err := copyFiles(root, tmp, "package.json", lockName, ".npmrc", "pnpm-workspace.yaml"); err != nil {
		return nil, err
	}
	if !exists(filepath.Join(tmp, "package.json")) {
		_ = os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"depguard-check","version":"0.0.0"}`), 0o600)
	}
	extra := []string{"--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"}
	if lockName == "pnpm-lock.yaml" {
		extra = []string{"--lockfile-only", "--ignore-scripts"}
	}
	if _, err := runTool(tmp, bin, append(args, extra...), nil); err != nil {
		return nil, err
	}
	r := &resolution{}
	if !global {
		if b, err := os.ReadFile(filepath.Join(root, lockName)); err == nil {
			r.req.Before = []checkFile{{lockName, string(b)}}
		}
	}
	after, err := os.ReadFile(filepath.Join(tmp, lockName))
	if err != nil {
		return nil, fmt.Errorf("resolution produced no %s", lockName)
	}
	r.req.After = []checkFile{{lockName, string(after)}}
	if b, err := os.ReadFile(filepath.Join(tmp, "package.json")); err == nil {
		r.req.Manifests = []checkFile{{"package.json", string(b)}}
	}
	r.key = hashKey(lockName, after)
	return r, nil
}

// lockfileOnly checks every package in an existing lockfile.
func lockfileOnly(root, lockName string, manifests ...string) (*resolution, error) {
	b, err := os.ReadFile(filepath.Join(root, lockName))
	if err != nil {
		return nil, err
	}
	r := &resolution{key: hashKey(lockName, b)}
	r.req.After = []checkFile{{lockName, string(b)}}
	for _, m := range manifests {
		if mb, err := os.ReadFile(filepath.Join(root, m)); err == nil {
			r.req.Manifests = append(r.req.Manifests, checkFile{m, string(mb)})
		}
	}
	return r, nil
}

// ---------------------------------------------------------------- Python

func resolvePip(inv invocation, bin string) (*resolution, error) {
	report, err := os.CreateTemp("", "depguard-pip-*.json")
	if err != nil {
		return nil, err
	}
	report.Close()
	defer os.Remove(report.Name())
	var args []string
	done := false
	for _, a := range inv.args {
		args = append(args, a)
		if !done && a == "install" {
			args = append(args, "--dry-run", "--ignore-installed", "--quiet", "--report", report.Name())
			done = true
		}
	}
	if _, err := runTool("", bin, args, nil); err != nil {
		return nil, err
	}
	var rep struct {
		Install []struct {
			Requested bool `json:"requested"`
			Metadata  struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"metadata"`
		} `json:"install"`
	}
	b, _ := os.ReadFile(report.Name())
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("pip report: %w (pip 22.2+ is required for a full check)", err)
	}
	r := &resolution{key: hashKey("pip", b)}
	for _, i := range rep.Install {
		d := i.Requested
		r.req.Packages = append(r.req.Packages, checkPkg{"pypi", i.Metadata.Name, i.Metadata.Version, &d})
	}
	return r, nil
}

var uvWouldInstall = regexp.MustCompile(`^\s*\+\s+([A-Za-z0-9._\-\[\]]+)==(\S+)`)

func resolveUV(inv invocation, dir, bin string) (*resolution, error) {
	if strings.HasPrefix(inv.sub, "pip ") {
		outp, err := runTool("", bin, append(slicesClone(inv.args), "--dry-run"), nil)
		if err != nil {
			return nil, err
		}
		r := &resolution{key: hashKey("uv-pip", outp)}
		sc := bufio.NewScanner(bytes.NewReader(outp))
		for sc.Scan() {
			if m := uvWouldInstall.FindStringSubmatch(sc.Text()); m != nil {
				name := m[1]
				if i := strings.Index(name, "["); i > 0 {
					name = name[:i]
				}
				r.req.Packages = append(r.req.Packages, checkPkg{Ecosystem: "pypi", Name: name, Version: m[2]})
			}
		}
		return r, nil
	}
	root := findUp(dir, "pyproject.toml")
	if root == "" {
		return nil, errors.New("no pyproject.toml found")
	}
	files := append([]string{"pyproject.toml", "uv.lock", ".python-version"}, readmes(root)...)
	args := []string{"lock"}
	if inv.sub == "add" {
		args = append(slicesClone(inv.args), "--no-sync")
	}
	return lockResolve(root, bin, args, "uv.lock", "pyproject.toml", len(inv.specs) > 0, files)
}

func resolvePoetry(inv invocation, dir, bin string) (*resolution, error) {
	root := findUp(dir, "pyproject.toml")
	if root == "" {
		return nil, errors.New("no pyproject.toml found")
	}
	if inv.sub == "install" && exists(filepath.Join(root, "poetry.lock")) {
		return lockfileOnly(root, "poetry.lock", "pyproject.toml")
	}
	args := []string{"lock"}
	if inv.sub == "add" {
		args = append(slicesClone(inv.args), "--lock")
	}
	files := append([]string{"pyproject.toml", "poetry.lock", "poetry.toml"}, readmes(root)...)
	return lockResolve(root, bin, args, "poetry.lock", "pyproject.toml", len(inv.specs) > 0, files)
}

// lockResolve runs a lock-only command in a temp copy; with diff set, only
// packages not already in the current lockfile are checked.
func lockResolve(root, bin string, args []string, lockName, manifest string, diff bool, files []string) (*resolution, error) {
	tmp, err := os.MkdirTemp("", "depguard-lock-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := copyFiles(root, tmp, files...); err != nil {
		return nil, err
	}
	if _, err := runTool(tmp, bin, args, nil); err != nil {
		return nil, err
	}
	after, err := os.ReadFile(filepath.Join(tmp, lockName))
	if err != nil {
		return nil, fmt.Errorf("resolution produced no %s", lockName)
	}
	r := &resolution{key: hashKey(lockName, after)}
	r.req.After = []checkFile{{lockName, string(after)}}
	if b, err := os.ReadFile(filepath.Join(tmp, manifest)); err == nil {
		r.req.Manifests = []checkFile{{manifest, string(b)}}
	}
	if b, err := os.ReadFile(filepath.Join(root, lockName)); err == nil && diff {
		r.req.Before = []checkFile{{lockName, string(b)}}
	}
	return r, nil
}

func readmes(root string) []string {
	m, _ := filepath.Glob(filepath.Join(root, "README*"))
	out := make([]string, 0, len(m))
	for _, f := range m {
		out = append(out, filepath.Base(f))
	}
	return out
}

// ---------------------------------------------------------------- Go

type goModule struct {
	Path     string
	Version  string
	Main     bool
	Indirect bool
	Replace  *goModule
}

func resolveGo(inv invocation, dir, bin string) (*resolution, error) {
	env := []string{"GOFLAGS=-mod=mod", "GOWORK=off"}
	if inv.sub == "install" && len(inv.specs) > 0 {
		// go install pkg@version builds outside any module: resolve it in a scratch module.
		tmp, err := os.MkdirTemp("", "depguard-go-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		if _, err := runTool(tmp, bin, []string{"mod", "init", "depguard.check/tmp"}, env); err != nil {
			return nil, err
		}
		if _, err := runTool(tmp, bin, append([]string{"get"}, inv.specs...), env); err != nil {
			return nil, err
		}
		return goList(tmp, bin, nil)
	}
	root := findUp(dir, "go.mod")
	if root == "" {
		return nil, errors.New("no go.mod found")
	}
	if inv.sub != "get" {
		return goList(root, bin, nil)
	}
	before, err := goModules(root, bin)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "depguard-go-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := copyFiles(root, tmp, "go.mod", "go.sum"); err != nil {
		return nil, err
	}
	// Go runs no code while fetching modules, so this is safe to do for real in the copy.
	if _, err := runTool(tmp, bin, inv.args, env); err != nil {
		return nil, err
	}
	return goList(tmp, bin, before)
}

func goList(dir, bin string, before map[string]bool) (*resolution, error) {
	mods, err := goModuleList(dir, bin)
	if err != nil {
		return nil, err
	}
	r := &resolution{}
	var keyParts []string
	for _, m := range mods {
		if m.Main || m.Version == "" {
			continue
		}
		if m.Replace != nil && m.Replace.Version != "" {
			m.Path, m.Version = m.Replace.Path, m.Replace.Version
		}
		id := m.Path + "@" + m.Version
		keyParts = append(keyParts, id)
		if before[id] {
			continue
		}
		d := !m.Indirect
		r.req.Packages = append(r.req.Packages, checkPkg{"go", m.Path, m.Version, &d})
	}
	r.key = hashKey("go", []byte(strings.Join(keyParts, "\n")))
	return r, nil
}

func goModules(dir, bin string) (map[string]bool, error) {
	mods, err := goModuleList(dir, bin)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, m := range mods {
		if m.Replace != nil && m.Replace.Version != "" {
			m.Path, m.Version = m.Replace.Path, m.Replace.Version
		}
		out[m.Path+"@"+m.Version] = true
	}
	return out, nil
}

func goModuleList(dir, bin string) ([]goModule, error) {
	outp, err := runTool(dir, bin, []string{"list", "-m", "-json", "all"}, []string{"GOFLAGS=-mod=mod", "GOWORK=off"})
	if err != nil {
		return nil, err
	}
	var mods []goModule
	dec := json.NewDecoder(bytes.NewReader(outp))
	for {
		var m goModule
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go list: %w", err)
		}
		mods = append(mods, m)
	}
	return mods, nil
}

// ---------------------------------------------------------------- Rust

func resolveCargo(inv invocation, dir, bin string) (*resolution, error) {
	if inv.global { // cargo install <crate>: check the crate itself
		return cargoInstall(inv)
	}
	root := findUp(dir, "Cargo.toml")
	if root == "" {
		return nil, errors.New("no Cargo.toml found")
	}
	if inv.sub != "add" && inv.sub != "update" && exists(filepath.Join(root, "Cargo.lock")) {
		return lockfileOnly(root, "Cargo.lock", "Cargo.toml")
	}
	tmp, err := os.MkdirTemp("", "depguard-cargo-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := copyFiles(root, tmp, "Cargo.toml", "Cargo.lock"); err != nil {
		return nil, err
	}
	// cargo needs a target to read the manifest; build scripts never run here.
	_ = os.MkdirAll(filepath.Join(tmp, "src"), 0o700)
	for _, f := range []string{"src/main.rs", "src/lib.rs"} {
		if exists(filepath.Join(root, f)) {
			_ = os.WriteFile(filepath.Join(tmp, f), nil, 0o600)
		}
	}
	if !exists(filepath.Join(tmp, "src/main.rs")) && !exists(filepath.Join(tmp, "src/lib.rs")) {
		_ = os.WriteFile(filepath.Join(tmp, "src/lib.rs"), nil, 0o600)
	}
	if inv.sub == "add" || inv.sub == "update" {
		if _, err := runTool(tmp, bin, inv.args, nil); err != nil {
			return nil, err
		}
	}
	if _, err := runTool(tmp, bin, []string{"metadata", "--format-version", "1"}, nil); err != nil {
		return nil, err
	}
	after, err := os.ReadFile(filepath.Join(tmp, "Cargo.lock"))
	if err != nil {
		return nil, errors.New("resolution produced no Cargo.lock")
	}
	r := &resolution{key: hashKey("Cargo.lock", after)}
	r.req.After = []checkFile{{"Cargo.lock", string(after)}}
	if b, err := os.ReadFile(filepath.Join(tmp, "Cargo.toml")); err == nil {
		r.req.Manifests = []checkFile{{"Cargo.toml", string(b)}}
	}
	if b, err := os.ReadFile(filepath.Join(root, "Cargo.lock")); err == nil && inv.sub == "add" {
		r.req.Before = []checkFile{{"Cargo.lock", string(b)}}
	}
	return r, nil
}

// cargoInstall looks up the version cargo would install from crates.io.
func cargoInstall(inv invocation) (*resolution, error) {
	r := &resolution{partial: true, note: "checked the crate itself; its dependencies are resolved at build time"}
	t := true
	for _, s := range inv.specs {
		name, version, ok := pinned("cargo", s)
		if !ok {
			name = s
			v, err := cratesMaxVersion(name)
			if err != nil {
				return nil, err
			}
			version = v
		}
		r.req.Packages = append(r.req.Packages, checkPkg{"cargo", name, version, &t})
	}
	return r, nil
}

func cratesMaxVersion(name string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://crates.io/api/v1/crates/"+name, nil)
	req.Header.Set("User-Agent", "depguard-cli/"+version)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var v struct {
		Crate struct {
			MaxStable string `json:"max_stable_version"`
		} `json:"crate"`
	}
	if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&v) != nil || v.Crate.MaxStable == "" {
		return "", fmt.Errorf("crate %s not found on crates.io", name)
	}
	return v.Crate.MaxStable, nil
}

// ---------------------------------------------------------------- helpers

// runTool runs the real tool quietly and returns its stdout; stderr is
// included in the error. DEPGUARD_ACTIVE stops shims from checking again.
func runTool(dir, bin string, args, env []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "DEPGUARD_ACTIVE=1", "npm_config_audit=false", "npm_config_fund=false"), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return nil, fmt.Errorf("%s %s: %v\n%s", filepath.Base(bin), strings.Join(args, " "), err, lastLines(msg, 6))
	}
	return append(stdout.Bytes(), stderr.Bytes()...), nil
}

func lastLines(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

func copyFiles(from, to string, names ...string) error {
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(from, n))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, n), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func findUp(dir, name string) string {
	dir, _ = filepath.Abs(dir)
	for {
		if exists(filepath.Join(dir, name)) {
			return dir
		}
		p := filepath.Dir(dir)
		if p == dir {
			return ""
		}
		dir = p
	}
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func slicesClone(s []string) []string { return append([]string(nil), s...) }
