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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
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

// errNeedsBuild: the resolution would have to build a source package (run its code).
var errNeedsBuild = errors.New("cannot resolve without building packages")

// resolve works out the packages an install would add, in a temporary copy of
// the project with install scripts disabled. bin is the real tool.
func resolve(inv invocation, dir, bin string) (*resolution, error) {
	if inv.exec || (inv.tool == "cargo" && inv.global) {
		return resolveNamed(inv, dir)
	}
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

// pathFlags point a package manager at another directory. During resolution an
// absolute one would reach the real project, so it is dropped; relative ones
// resolve inside the temporary copy.
var pathFlags = set("--prefix", "-C", "--dir", "--cwd", "--modules-folder", "--manifest-path", "--directory", "--project", "-modfile")

func safeArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		flag, val, hasVal := strings.Cut(args[i], "=")
		if pathFlags[flag] {
			if !hasVal && i+1 < len(args) {
				val = args[i+1]
			}
			if filepath.IsAbs(val) {
				if !hasVal {
					i++
				}
				continue
			}
		}
		out = append(out, args[i])
	}
	return out
}

// ---------------------------------------------------------------- JavaScript

func resolveJS(inv invocation, dir, bin string) (*resolution, error) {
	pkgDir, root, members := dir, dir, []string(nil)
	if !inv.global {
		if r := findUp(dir, "package.json"); r != "" {
			pkgDir = r
		}
		root, members = jsWorkspace(pkgDir)
	}
	rel, _ := filepath.Rel(root, pkgDir)
	lockName := map[string]string{"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "yarn": "yarn.lock"}[inv.tool]
	if inv.tool == "npm" && exists(filepath.Join(root, "npm-shrinkwrap.json")) {
		lockName = "npm-shrinkwrap.json"
	}
	whole := len(inv.specs) == 0 && !inv.global
	// A frozen install (npm ci, yarn/pnpm install with a lockfile) installs exactly the lockfile.
	if whole && exists(filepath.Join(root, lockName)) && (inv.sub == "ci" || inv.sub == "clean-install" || inv.tool == "yarn" || inv.tool == "pnpm") {
		return lockfileOnly(root, lockName, "package.json")
	}
	sub := "install"
	switch {
	case inv.tool == "npm" && (inv.sub == "update" || inv.sub == "up" || inv.sub == "upgrade" || inv.sub == "udpate"):
		sub = "update"
	case inv.tool != "npm" && inv.sub != "":
		sub = inv.sub
	}
	args := append([]string{sub}, jsInstallArgs(inv)...)
	if inv.tool != "yarn" {
		return jsResolve(root, rel, members, bin, args, lockName, inv.global)
	}
	if yarnBerry(bin, pkgDir) {
		return jsResolve(root, rel, members, bin, args, lockName, inv.global)
	}
	// Yarn classic cannot update only the lockfile: resolve the same request with npm and
	// check the packages yarn.lock does not have yet.
	npm, err := realTool("npm")
	if err != nil {
		return nil, errors.New("yarn (classic) installs are checked by resolving with npm, which was not found")
	}
	r, err := jsResolve(root, rel, members, npm, append([]string{"install"}, jsInstallArgs(inv)...), "package-lock.json", inv.global)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	if b, err := os.ReadFile(filepath.Join(root, "yarn.lock")); err == nil && !inv.global {
		known = yarnLockVersions(b)
	}
	direct := map[string]bool{}
	for _, s := range inv.specs {
		direct[specName("npm", s)] = true
	}
	pkgs, err := npmLockPackages([]byte(r.req.After[0].Content))
	if err != nil {
		return nil, err
	}
	r.req = checkRequest{}
	for _, p := range pkgs {
		if !known[p.Name+"@"+p.Version] {
			d := direct[p.Name] && *p.Direct
			p.Direct = &d
			r.req.Packages = append(r.req.Packages, p)
		}
	}
	r.note = "approximate: resolved with npm"
	return r, nil
}

// jsInstallArgs drops the subcommand, global flags and absolute path flags.
func jsInstallArgs(inv invocation) []string {
	var out []string
	skipped := false
	for _, a := range safeArgs(inv.args) {
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

// jsResolve runs a lockfile-only install in a temporary copy of the project (the
// workspace root and its members' manifests), in the copy of the package dir rel.
func jsResolve(root, rel string, members []string, bin string, args []string, lockName string, global bool) (*resolution, error) {
	tmp, err := os.MkdirTemp("", "depguard-js-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if global {
		rel = "."
		if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"depguard-global","version":"0.0.0"}`), 0o600); err != nil {
			return nil, err
		}
	} else {
		files := []string{"package.json", lockName, ".npmrc", "pnpm-workspace.yaml", ".yarnrc.yml", filepath.Join(rel, "package.json")}
		for _, m := range members {
			files = append(files, filepath.Join(m, "package.json"))
		}
		if err := copyFiles(root, tmp, files...); err != nil {
			return nil, err
		}
		for _, d := range []string{".yarn/releases", ".yarn/plugins"} { // yarn berry runs from the repo
			if err := copyTree(root, tmp, d); err != nil {
				return nil, err
			}
		}
	}
	if !exists(filepath.Join(tmp, "package.json")) {
		_ = os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name":"depguard-check","version":"0.0.0"}`), 0o600)
	}
	var env []string
	switch lockName {
	case "pnpm-lock.yaml":
		args = append(args, "--lockfile-only", "--ignore-scripts")
	case "yarn.lock": // berry
		args = append(args, "--mode", "update-lockfile")
		env = []string{"YARN_ENABLE_SCRIPTS=0", "YARN_ENABLE_IMMUTABLE_INSTALLS=0", "YARN_ENABLE_TELEMETRY=0"}
	default:
		args = append(args, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund")
	}
	if _, err := runTool(filepath.Join(tmp, rel), bin, args, env); err != nil {
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
	manifests := []string{"package.json"}
	if rel != "." {
		manifests = append(manifests, filepath.Join(rel, "package.json"))
	}
	for _, m := range manifests {
		if b, err := os.ReadFile(filepath.Join(tmp, m)); err == nil {
			r.req.Manifests = append(r.req.Manifests, checkFile{filepath.ToSlash(m), string(b)})
		}
	}
	r.key = hashKey(lockName, after)
	return r, nil
}

// jsWorkspace returns the npm/yarn/pnpm workspace root above pkgDir and its member
// directories (relative to the root), or pkgDir itself outside a workspace.
func jsWorkspace(pkgDir string) (string, []string) {
	for d := pkgDir; ; {
		if globs := jsWorkspaceGlobs(d); len(globs) > 0 {
			members := globMembers(d, globs, "package.json")
			if rel, _ := filepath.Rel(d, pkgDir); rel == "." || slices.Contains(members, rel) {
				return d, members
			}
			break
		}
		p := filepath.Dir(d)
		if p == d || repoBoundary(d) {
			break
		}
		d = p
	}
	return pkgDir, nil
}

func jsWorkspaceGlobs(dir string) []string {
	if b, err := os.ReadFile(filepath.Join(dir, "pnpm-workspace.yaml")); err == nil {
		var ws struct {
			Packages []string `yaml:"packages"`
		}
		_ = yaml.Unmarshal(b, &ws)
		return ws.Packages
	}
	var pj struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil || json.Unmarshal(b, &pj) != nil || len(pj.Workspaces) == 0 {
		return nil
	}
	var globs []string
	if json.Unmarshal(pj.Workspaces, &globs) != nil { // {"packages": [...]} (yarn classic)
		var obj struct {
			Packages []string `json:"packages"`
		}
		_ = json.Unmarshal(pj.Workspaces, &obj)
		globs = obj.Packages
	}
	return globs
}

// globMembers lists the directories under root (relative) matching workspace globs that contain file.
func globMembers(root string, globs []string, file string) []string {
	var out []string
	for _, g := range globs {
		g = strings.TrimSuffix(strings.TrimPrefix(g, "./"), "/")
		if g == "" || strings.HasPrefix(g, "!") {
			continue
		}
		pats := []string{g}
		if b, ok := strings.CutSuffix(g, "/**"); ok { // ponytail: ** matches two levels deep
			pats = []string{b, b + "/*", b + "/*/*"}
		}
		for _, p := range pats {
			m, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(p), file))
			for _, f := range m {
				rel, err := filepath.Rel(root, filepath.Dir(f))
				if err != nil || rel == "." || strings.HasPrefix(rel, "..") || strings.Contains(rel, "node_modules") || slices.Contains(out, rel) {
					continue
				}
				out = append(out, rel)
			}
		}
	}
	return out
}

// yarnBerry: yarn 2+ (per project, through corepack or yarnPath).
func yarnBerry(bin, dir string) bool {
	out, err := runTool(dir, bin, []string{"--version"}, []string{"COREPACK_ENABLE_DOWNLOAD_PROMPT=0"})
	if err != nil {
		return false
	}
	major, _, _ := strings.Cut(strings.TrimSpace(string(out)), ".")
	n, _ := strconv.Atoi(major)
	return n >= 2
}

// yarnLockVersions returns name@version for every entry of a yarn.lock (classic or berry).
func yarnLockVersions(b []byte) map[string]bool {
	out := map[string]bool{}
	var names []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":"):
			// "@babel/core@^7.0.0", "@babel/core@^7.1.0":   or   "lodash@npm:^4.17.0":
			names = names[:0]
			for _, k := range strings.Split(strings.TrimSuffix(line, ":"), ",") {
				k = strings.Trim(strings.TrimSpace(k), `"`)
				if at := strings.LastIndex(k, "@"); at > 0 { // name@range, name@npm:range
					names = append(names, k[:at])
				}
			}
		case strings.HasPrefix(line, "  version"):
			v := strings.Trim(strings.TrimSpace(strings.TrimLeft(strings.TrimPrefix(line, "  version"), ": ")), `"`)
			for _, n := range names {
				out[n+"@"+v] = true
			}
			names = names[:0]
		}
	}
	return out
}

// npmLockPackages lists the installed packages of a package-lock.json (v2/v3).
func npmLockPackages(b []byte) ([]checkPkg, error) {
	var lock struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	var out []checkPkg
	for path, p := range lock.Packages {
		i := strings.LastIndex(path, "node_modules/")
		if i < 0 || p.Link || p.Version == "" {
			continue
		}
		top := i == 0 // node_modules/x, not nested under another package
		out = append(out, checkPkg{Ecosystem: "npm", Name: firstNonEmpty(p.Name, path[i+len("node_modules/"):]), Version: p.Version, Direct: &top})
	}
	slices.SortFunc(out, func(a, b checkPkg) int { return strings.Compare(a.Name+"@"+a.Version, b.Name+"@"+b.Version) })
	return slices.CompactFunc(out, func(a, b checkPkg) bool { return a.Name == b.Name && a.Version == b.Version }), nil
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

// asBuildError marks failures caused by refusing to build source distributions.
func asBuildError(err error, pip bool) error {
	m := strings.ToLower(err.Error())
	if (pip && notFound(err)) || strings.Contains(m, "build") || strings.Contains(m, "no usable wheels") {
		return fmt.Errorf("%w: %v", errNeedsBuild, err)
	}
	return err
}

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
			// --only-binary: building an sdist would run its setup code.
			args = append(args, "--dry-run", "--ignore-installed", "--quiet", "--only-binary=:all:", "--report", report.Name())
			done = true
		}
	}
	if _, err := runTool("", bin, args, nil); err != nil {
		// With --only-binary, "no matching distribution" usually means only sdists exist.
		return nil, asBuildError(err, true)
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
		outp, err := runTool("", bin, append(slices.Clone(inv.args), "--dry-run", "--no-build"), nil)
		if err != nil {
			return nil, asBuildError(err, false)
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
	if inv.sub == "sync" && (slices.Contains(inv.args, "--frozen") || slices.Contains(inv.args, "--locked")) && exists(filepath.Join(root, "uv.lock")) {
		return lockfileOnly(root, "uv.lock", "pyproject.toml")
	}
	files := append([]string{"pyproject.toml", "uv.lock", ".python-version"}, readmes(root)...)
	args := append([]string{"lock", "--no-build"}, uvUpgradeFlags(inv.args)...)
	if inv.sub == "add" {
		args = append(safeArgs(inv.args), "--no-sync", "--no-build")
	}
	r, err := lockResolve(root, bin, args, "uv.lock", "pyproject.toml", len(inv.specs) > 0, files)
	if err != nil {
		return nil, asBuildError(err, false)
	}
	return r, nil
}

// uvUpgradeFlags are the upgrade requests of `uv lock`/`uv sync`, forwarded to the lock run.
func uvUpgradeFlags(args []string) []string {
	var out []string
	for i, a := range args {
		switch {
		case a == "-U" || a == "--upgrade" || strings.HasPrefix(a, "--upgrade-package="):
			out = append(out, a)
		case (a == "--upgrade-package" || a == "-P") && i+1 < len(args):
			out = append(out, a, args[i+1])
		}
	}
	return out
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
	if inv.sub == "add" || inv.sub == "update" {
		args = append(safeArgs(inv.args), "--lock")
	}
	files := append([]string{"pyproject.toml", "poetry.lock", "poetry.toml"}, readmes(root)...)
	// Poetry cannot be told not to build: when a package needs building, it fails here
	// (no build backend in the copy) and depguard falls back to a partial check.
	r, err := lockResolve(root, bin, args, "poetry.lock", "pyproject.toml", len(inv.specs) > 0, files)
	if err != nil {
		return nil, asBuildError(err, false)
	}
	return r, nil
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
	tmp, err := os.MkdirTemp("", "depguard-go-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if inv.sub == "install" {
		// go install pkg@version builds outside any module: resolve it in a scratch module.
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
	// Everything runs in a copy of go.mod/go.sum: -mod=mod may rewrite them.
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), rewriteReplaces(mod, root), 0o600); err != nil {
		return nil, err
	}
	if err := copyFiles(root, tmp, "go.sum"); err != nil {
		return nil, err
	}
	if inv.sub != "get" { // go mod tidy / download: the module graph of go.mod
		return goList(tmp, bin, nil)
	}
	before, err := goModules(tmp, bin)
	if err != nil {
		return nil, err
	}
	// Go runs no code while fetching modules, so this is safe to do for real in the copy.
	if _, err := runTool(tmp, bin, safeArgs(inv.args), env); err != nil {
		return nil, err
	}
	return goList(tmp, bin, before)
}

// localReplace matches the target of `replace x => ../local/path`.
var localReplace = regexp.MustCompile(`(?m)(=>\s*)(\.\.?(?:[/\\]\S*)?)([ \t]*(?://.*)?\r?)$`)

// rewriteReplaces makes relative replace paths absolute (relative to root) so a
// copy of go.mod elsewhere still finds the local modules.
func rewriteReplaces(mod []byte, root string) []byte {
	return localReplace.ReplaceAllFunc(mod, func(m []byte) []byte {
		sm := localReplace.FindSubmatch(m)
		p := filepath.Join(root, string(sm[2]))
		if strings.ContainsAny(p, " \t\"") {
			p = strconv.Quote(p)
		}
		return []byte(string(sm[1]) + p + string(sm[3]))
	})
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
	crate := findUp(dir, "Cargo.toml")
	if crate == "" {
		return nil, errors.New("no Cargo.toml found")
	}
	root, members := cargoWorkspace(crate)
	if inv.sub == "fetch" && exists(filepath.Join(root, "Cargo.lock")) {
		return lockfileOnly(root, "Cargo.lock", "Cargo.toml")
	}
	tmp, err := os.MkdirTemp("", "depguard-cargo-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := copyFiles(root, tmp, "Cargo.lock"); err != nil {
		return nil, err
	}
	// cargo needs each manifest and a target to read it; build scripts never run here.
	for _, m := range append([]string{"."}, members...) {
		if err := copyFiles(root, tmp, filepath.Join(m, "Cargo.toml")); err != nil {
			return nil, err
		}
		from, to := filepath.Join(root, m), filepath.Join(tmp, m)
		_ = os.MkdirAll(filepath.Join(to, "src"), 0o700)
		for _, f := range []string{"src/main.rs", "src/lib.rs"} {
			if exists(filepath.Join(from, f)) {
				_ = os.WriteFile(filepath.Join(to, f), nil, 0o600)
			}
		}
		if !exists(filepath.Join(to, "src/main.rs")) && !exists(filepath.Join(to, "src/lib.rs")) {
			_ = os.WriteFile(filepath.Join(to, "src/lib.rs"), nil, 0o600)
		}
	}
	rel, _ := filepath.Rel(root, crate)
	work := filepath.Join(tmp, rel)
	if inv.sub == "add" || inv.sub == "update" || inv.sub == "generate-lockfile" {
		if _, err := runTool(work, bin, safeArgs(inv.args), nil); err != nil {
			return nil, err
		}
	}
	if _, err := runTool(work, bin, []string{"metadata", "--format-version", "1"}, nil); err != nil {
		return nil, err
	}
	after, err := os.ReadFile(filepath.Join(tmp, "Cargo.lock"))
	if err != nil {
		return nil, errors.New("resolution produced no Cargo.lock")
	}
	r := &resolution{key: hashKey("Cargo.lock", after)}
	r.req.After = []checkFile{{"Cargo.lock", string(after)}}
	if b, err := os.ReadFile(filepath.Join(work, "Cargo.toml")); err == nil {
		r.req.Manifests = []checkFile{{"Cargo.toml", string(b)}}
	}
	if b, err := os.ReadFile(filepath.Join(root, "Cargo.lock")); err == nil {
		r.req.Before = []checkFile{{"Cargo.lock", string(b)}}
	}
	return r, nil
}

var (
	cargoMembersRe = regexp.MustCompile(`(?s)\[workspace\][^\[]*?members\s*=\s*\[([^\]]*)\]`)
	quotedRe       = regexp.MustCompile(`"([^"]+)"`)
)

// cargoWorkspace returns the workspace root above crate and its member dirs
// (relative to the root), or crate itself outside a workspace.
func cargoWorkspace(crate string) (string, []string) {
	for d := crate; ; {
		if b, err := os.ReadFile(filepath.Join(d, "Cargo.toml")); err == nil && bytes.Contains(b, []byte("[workspace]")) {
			var globs []string
			if m := cargoMembersRe.FindSubmatch(b); m != nil {
				for _, q := range quotedRe.FindAllSubmatch(m[1], -1) {
					globs = append(globs, string(q[1]))
				}
			}
			members := globMembers(d, globs, "Cargo.toml")
			if rel, _ := filepath.Rel(d, crate); rel == "." || slices.Contains(members, rel) {
				return d, members
			}
			break
		}
		p := filepath.Dir(d)
		if p == d || repoBoundary(d) {
			break
		}
		d = p
	}
	return crate, nil
}

// ---------------------------------------------------------------- named packages

// resolveNamed checks only the packages named on the command line (npx, dlx, uvx,
// cargo install): the exact version given, else the registry's latest.
func resolveNamed(inv invocation, dir string) (*resolution, error) {
	eco := toolEcosystem[inv.tool]
	r := &resolution{partial: true}
	t := true
	var ids []string
	for _, s := range inv.specs {
		name, v, ok := pinned(inv.tool, s)
		if !ok {
			name = specName(eco, s)
			if inv.exec && eco == "npm" && findUp(dir, filepath.Join("node_modules", ".bin", name)) != "" {
				continue // npx runs the project's own copy, checked when it was installed
			}
			lv, err := latestVersion(eco, name)
			if err != nil {
				return nil, err
			}
			v = lv
		}
		r.req.Packages = append(r.req.Packages, checkPkg{eco, name, v, &t})
		ids = append(ids, name+"@"+v)
	}
	if len(ids) > 0 {
		r.key = hashKey("named-"+eco, []byte(strings.Join(ids, "\n")))
		r.note = "checked the named package; its dependencies are resolved when it is installed"
	}
	return r, nil
}

// specName strips the version or range from a package spec.
func specName(eco, s string) string {
	switch eco {
	case "npm":
		if at := strings.LastIndex(s, "@"); at > 0 {
			return s[:at]
		}
		return s
	case "pypi":
		if i := strings.IndexAny(s, "<>=!~[; "); i >= 0 {
			return s[:i]
		}
		return s
	}
	n, _, _ := strings.Cut(s, "@")
	return n
}

// latestVersion asks the public registry for a package's current version.
func latestVersion(eco, name string) (string, error) {
	u := map[string]string{
		"npm":   "https://registry.npmjs.org/" + strings.Replace(name, "/", "%2f", 1) + "/latest",
		"pypi":  "https://pypi.org/pypi/" + url.PathEscape(name) + "/json",
		"cargo": "https://crates.io/api/v1/crates/" + url.PathEscape(name),
	}[eco]
	if u == "" {
		return "", fmt.Errorf("no registry lookup for %s", eco)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("User-Agent", "depguard-cli/"+version)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var v struct {
		Version string `json:"version"` // npm
		Info    struct {
			Version string `json:"version"`
		} `json:"info"` // PyPI
		Crate struct {
			MaxStable string `json:"max_stable_version"`
		} `json:"crate"` // crates.io
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&v) != nil {
		return "", fmt.Errorf("%s not found in registry (%s)", name, eco)
	}
	if lv := firstNonEmpty(v.Version, v.Info.Version, v.Crate.MaxStable); lv != "" {
		return lv, nil
	}
	return "", fmt.Errorf("%s not found in registry (%s)", name, eco)
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

// copyFiles copies the named files (paths relative to from) that exist.
func copyFiles(from, to string, names ...string) error {
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(from, n))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(to, n)), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, n), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// copyTree copies the directory dir (relative to from) if it exists.
func copyTree(from, to, dir string) error {
	err := filepath.WalkDir(filepath.Join(from, dir), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		return copyFiles(from, to, rel)
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
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
