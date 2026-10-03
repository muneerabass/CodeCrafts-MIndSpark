package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

// guardedTools are the package managers depguard wraps (shims and `depguard <tool>`).
var guardedTools = []string{"npm", "npx", "pnpm", "yarn", "pip", "pip3", "uv", "uvx", "poetry", "go", "cargo"}

func isGuardedTool(s string) bool {
	for _, t := range guardedTools {
		if s == t {
			return true
		}
	}
	return false
}

// invocation is a classified package-manager command.
type invocation struct {
	tool    string   // npm, npx, pnpm, yarn, pip, uv, uvx, poetry, go, cargo
	sub     string   // install, add, get, ...
	args    []string // the full original arguments (passed to the real tool)
	specs   []string // packages named on the command line (may carry versions)
	install bool     // installs or changes dependencies: must be checked
	global  bool     // global/user install (npm -g, cargo install): not tied to a project
	exec    bool     // fetches a package and runs it (npx, dlx, uvx): only the named packages are checked
}

// Flags that take a value, per tool, so their value is not mistaken for a package.
var valueFlags = map[string]map[string]bool{
	"npm":    set("--registry", "--prefix", "-C", "-w", "--workspace", "--tag", "--cache", "--userconfig", "--globalconfig", "--loglevel", "--omit", "--include", "--package", "-p", "-c", "--call"),
	"pnpm":   set("--filter", "-F", "--registry", "--dir", "-C", "--store-dir", "--workspace", "--loglevel", "--package"),
	"yarn":   set("--registry", "--cwd", "--modules-folder", "--cache-folder", "--network-timeout", "--mutex", "--package", "-p"),
	"pip":    set("-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-t", "--target", "--prefix", "--root", "-f", "--find-links", "--trusted-host", "--src", "-e", "--editable", "--report", "--log", "--log-file", "--cache-dir", "--proxy", "--timeout", "--retries", "--cert", "--client-cert", "--only-binary", "--no-binary", "--platform", "--python-version", "--implementation", "--abi", "--progress-bar"),
	"uv":     set("-r", "--requirement", "-c", "--constraint", "--index-url", "--extra-index-url", "--index", "--default-index", "--find-links", "-f", "--python", "-p", "--group", "--optional", "--extra", "--package", "--directory", "--project", "--upgrade-package", "-P", "--from", "--with", "-w"),
	"poetry": set("--group", "-G", "--with", "--without", "--only", "--source", "--extras", "-E", "--python", "--directory", "-C", "--project", "-P"),
	"go":     set("-C", "-modfile", "-tags", "-ldflags", "-gcflags", "-o", "-p", "-run"),
	"cargo":  set("--features", "-F", "--package", "-p", "--manifest-path", "--registry", "--rename", "--target", "--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path", "--root", "--index", "-Z", "--color", "--config", "--target-dir", "-j", "--jobs", "--profile"),
}

func init() {
	valueFlags["npx"] = valueFlags["npm"]
	valueFlags["uvx"] = valueFlags["uv"]
}

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// installSubs: subcommands that add or change dependencies.
var installSubs = map[string]map[string]bool{
	"npm":    set("install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "add", "update", "up", "upgrade", "udpate", "ci", "clean-install", "install-test", "it", "install-ci-test", "cit", "exec", "x"),
	"pnpm":   set("add", "install", "i", "update", "up", "upgrade", "dlx"),
	"yarn":   set("add", "install", "upgrade", "up", "dlx"),
	"pip":    set("install"),
	"uv":     set("add", "sync", "lock"),
	"poetry": set("add", "install", "update", "lock"),
	"go":     set("get", "install", "mod"),
	"cargo":  set("add", "install", "update", "fetch", "generate-lockfile"),
}

// otherSubs run code or other commands: their arguments never name a subcommand
// (`npm run install`, `cargo test -- add`).
var otherSubs = map[string]map[string]bool{
	"npm":    set("run", "run-script", "rum", "urn", "test", "tst", "t", "start", "stop", "restart", "explore", "rebuild", "rb"),
	"pnpm":   set("run", "exec", "test", "t", "start", "create"),
	"yarn":   set("run", "exec", "node", "test", "start", "workspace", "workspaces", "create"),
	"uv":     set("run", "tool", "pip"),
	"poetry": set("run", "shell"),
	"go":     set("run", "test", "build", "vet", "generate", "tool", "list", "env", "work", "fmt", "clean", "doc", "fix", "version"),
	"cargo":  set("run", "test", "build", "check", "clippy", "bench", "doc", "fmt", "clean", "tree", "metadata"),
}

// execSubs fetch a package and run it.
var execSubs = map[string]map[string]bool{"npm": set("exec", "x"), "pnpm": set("dlx"), "yarn": set("dlx")}

// helpFlag: --help/--version print and exit; -v is --version for the JS tools, -V for the others.
func helpFlag(tool, a string) bool {
	switch a {
	case "--help", "-h", "--version":
		return true
	case "-v":
		return toolEcosystem[tool] == "npm"
	case "-V":
		return tool == "pip" || tool == "uv" || tool == "uvx" || tool == "poetry" || tool == "cargo"
	}
	return false
}

func classify(tool string, args []string) invocation {
	if tool == "pip3" {
		tool = "pip"
	}
	inv := invocation{tool: tool, args: args}
	if tool == "npx" || tool == "uvx" {
		return execInvocation(inv, args)
	}
	vf := valueFlags[tool]
	var pos []int // indexes of positional arguments
	help, version := false, ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		flag, val, hasVal := strings.Cut(a, "=")
		switch {
		case a == "--":
			for j := i + 1; j < len(args); j++ {
				pos = append(pos, j)
			}
			i = len(args)
		case tool == "cargo" && strings.HasPrefix(a, "+"): // +toolchain
		case strings.HasPrefix(a, "-") && a != "-":
			if a == "-g" || a == "--global" || a == "--location=global" {
				inv.global = true
			}
			if vf[flag] && !hasVal {
				if i++; i < len(args) {
					val = args[i]
				}
			} else if helpFlag(tool, a) {
				help = true
			}
			if tool == "cargo" && (flag == "--version" || flag == "--vers") {
				version = val
			}
		default:
			pos = append(pos, i)
		}
	}
	si := -1
	for k, p := range pos {
		if installSubs[tool][args[p]] || otherSubs[tool][args[p]] {
			si = k
			break
		}
	}
	if si < 0 && len(pos) > 0 {
		si = 0
	}
	if si < 0 {
		// bare `yarn` installs; `yarn --version` does not
		inv.install = tool == "yarn" && !help
		return inv
	}
	inv.sub = args[pos[si]]
	var rest []string
	for _, p := range pos[si+1:] {
		rest = append(rest, args[p])
	}
	// Fetch-and-run forms: flags after the package belong to the command (`npx x --help` runs x).
	if execSubs[tool][inv.sub] {
		return execInvocation(inv, args[pos[si]+1:])
	}
	if tool == "uv" && inv.sub == "tool" && len(rest) > 0 && (rest[0] == "run" || rest[0] == "install") {
		return execInvocation(inv, args[pos[si+1]+1:])
	}
	if help {
		return inv
	}
	switch {
	case tool == "uv" && inv.sub == "pip" && len(rest) > 0 && (rest[0] == "install" || rest[0] == "sync"):
		inv.sub, inv.install, inv.specs = "pip "+rest[0], true, rest[1:]
		return inv
	case tool == "go" && inv.sub == "mod":
		inv.install = len(rest) > 0 && (rest[0] == "tidy" || rest[0] == "download")
		return inv
	case tool == "go" && inv.sub == "install":
		// only `go install pkg@version` fetches modules; `go install ./cmd/x` builds local code
		for _, s := range rest {
			if strings.Contains(s, "@") && !isLocalSpec(s) {
				inv.specs = append(inv.specs, s)
			}
		}
		inv.install = len(inv.specs) > 0
		return inv
	case tool == "cargo" && inv.sub == "install":
		inv.global = true
	}
	inv.install = installSubs[tool][inv.sub]
	if !inv.install {
		return inv
	}
	for _, s := range rest {
		if !isLocalSpec(s) {
			if version != "" && !strings.Contains(s, "@") {
				s += "@" + version // cargo install crate --version X
			}
			inv.specs = append(inv.specs, s)
		}
	}
	return inv
}

// execInvocation classifies `npx [opts] pkg args…` (and npm exec, pnpm/yarn dlx, uvx):
// options end at the package, everything after it belongs to the command being run.
func execInvocation(inv invocation, args []string) invocation {
	inv.install, inv.exec = true, true
	vf := valueFlags[inv.tool]
	pypi := toolEcosystem[inv.tool] == "pypi"
	// packages named by flags; --package/--from also mean the positional is a command, not a package
	nameFlags := map[bool]map[string]bool{true: set("--from", "--with", "-w"), false: set("--package", "-p")}[pypi]
	var named []string
	cmd, cmdIsPkg := "", true
	for i := 0; i < len(args) && cmd == ""; i++ {
		a := args[i]
		flag, val, hasVal := strings.Cut(a, "=")
		switch {
		case a == "--":
			if i+1 < len(args) {
				cmd = args[i+1]
			}
		case strings.HasPrefix(a, "-"):
			if helpFlag(inv.tool, a) {
				inv.install, inv.exec = false, false
				return inv
			}
			if vf[flag] && !hasVal {
				if i++; i < len(args) {
					val = args[i]
				}
			}
			if nameFlags[flag] {
				named = append(named, strings.Split(val, ",")...)
				cmdIsPkg = cmdIsPkg && (flag == "--with" || flag == "-w")
			}
		default:
			cmd = a
		}
	}
	if cmdIsPkg && cmd != "" {
		named = append([]string{cmd}, named...)
	}
	for _, s := range named {
		if s == "" || isLocalSpec(s) {
			continue
		}
		if pypi { // uvx ruff@0.5.0 = ruff==0.5.0
			if n, v, ok := strings.Cut(s, "@"); ok {
				s = n
				if v != "latest" {
					s += "==" + v
				}
			}
		}
		inv.specs = append(inv.specs, s)
	}
	inv.install = len(inv.specs) > 0
	inv.exec = inv.install
	return inv
}

// isLocalSpec: paths, archives and VCS URLs are not registry packages.
func isLocalSpec(s string) bool {
	return strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.Contains(s, "://") ||
		strings.HasPrefix(s, "git+") || strings.HasPrefix(s, "file:") || filepath.Ext(s) == ".tgz" ||
		filepath.Ext(s) == ".whl" || strings.HasSuffix(s, ".tar.gz")
}

var (
	// semver-style full version: 1.2.3, v1.2.3, 1.2.3-beta.1, v0.0.0-2023…-abcdef, v2.0.0+incompatible
	fullVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	// PEP 440 exact version (`==2.0`, `==1.0rc1`); wildcards are not exact
	pep440Exact = regexp.MustCompile(`^\d+(\.\d+)*[0-9A-Za-z.!+]*$`)
)

// pinned returns (name, version) when a spec names one exact version.
func pinned(tool, spec string) (name, version string, ok bool) {
	re := fullVersion
	switch toolEcosystem[tool] {
	case "npm":
		at := strings.LastIndex(spec, "@")
		if at <= 0 {
			return "", "", false
		}
		name, version = spec[:at], spec[at+1:]
	case "pypi":
		var found bool
		name, version, found = strings.Cut(spec, "==")
		if !found {
			return "", "", false
		}
		if i := strings.IndexAny(name, "["); i >= 0 {
			name = name[:i]
		}
		re = pep440Exact
	case "go", "cargo":
		var found bool
		name, version, found = strings.Cut(spec, "@")
		if !found {
			return "", "", false
		}
	}
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if !re.MatchString(version) {
		return "", "", false
	}
	return name, version, true
}

var toolEcosystem = map[string]string{"npm": "npm", "npx": "npm", "pnpm": "npm", "yarn": "npm", "pip": "pypi", "uv": "pypi", "uvx": "pypi", "poetry": "pypi", "go": "go", "cargo": "cargo"}
