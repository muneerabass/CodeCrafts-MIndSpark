package main

import (
	"path/filepath"
	"strings"
)

// guardedTools are the package managers depguard wraps (shims and `depguard <tool>`).
var guardedTools = []string{"npm", "pnpm", "yarn", "pip", "pip3", "uv", "poetry", "go", "cargo"}

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
	tool    string   // npm, pnpm, yarn, pip, uv, poetry, go, cargo
	sub     string   // install, add, get, ...
	args    []string // the full original arguments (passed to the real tool)
	specs   []string // packages named on the command line (may carry versions)
	install bool     // installs or changes dependencies: must be checked
	global  bool     // global/user install (npm -g, cargo install): not tied to a project
}

// Flags that take a value, per tool, so their value is not mistaken for a package.
var valueFlags = map[string]map[string]bool{
	"npm":    set("--registry", "--prefix", "-w", "--workspace", "--tag", "--cache", "--userconfig", "--omit", "--include"),
	"pnpm":   set("--filter", "-F", "--registry", "--dir", "-C", "--store-dir", "--workspace"),
	"yarn":   set("--registry", "--cwd", "--modules-folder", "--cache-folder"),
	"pip":    set("-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-t", "--target", "--prefix", "--root", "-f", "--find-links", "--python-version", "--platform", "--trusted-host", "--src", "-e", "--editable", "--report", "--log", "--cache-dir"),
	"uv":     set("-r", "--requirement", "-c", "--constraint", "--index-url", "--extra-index-url", "--python", "-p", "--group", "--optional", "--extra", "--package", "--directory", "--project", "--index"),
	"poetry": set("--group", "-G", "--source", "--extras", "-E", "--python", "--directory", "-C"),
	"go":     set("-C", "-modfile", "-tags", "-ldflags", "-gcflags", "-o", "-p"),
	"cargo":  set("--features", "-F", "--package", "-p", "--manifest-path", "--registry", "--rename", "--target", "--version", "--git", "--branch", "--tag", "--rev", "--path", "--root", "--index", "-Z"),
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
	"npm":    set("install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "add", "update", "up", "upgrade", "udpate", "ci", "clean-install", "install-test", "it", "install-ci-test", "cit"),
	"pnpm":   set("add", "install", "i", "update", "up", "upgrade"),
	"yarn":   set("add", "install", "upgrade", "up"),
	"pip":    set("install"),
	"uv":     set("add", "sync", "lock"),
	"poetry": set("add", "install", "update", "lock"),
	"go":     set("get", "install", "build", "run", "test", "mod"),
	"cargo":  set("add", "install", "build", "run", "test", "update", "fetch", "check"),
}

func classify(tool string, args []string) invocation {
	if tool == "pip3" {
		tool = "pip"
	}
	inv := invocation{tool: tool, args: args}
	vf := valueFlags[tool]
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(a, "-"):
			if a == "-g" || a == "--global" || a == "--location=global" {
				inv.global = true
			}
			if vf[a] && !strings.Contains(a, "=") {
				i++ // skip the flag's value
			}
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) == 0 {
		// bare `yarn` / `pnpm` install
		inv.install = tool == "yarn"
		return inv
	}
	inv.sub = positional[0]
	rest := positional[1:]
	switch {
	case tool == "uv" && inv.sub == "pip" && len(rest) > 0 && (rest[0] == "install" || rest[0] == "sync"):
		inv.sub, inv.install, inv.specs = "pip "+rest[0], true, rest[1:]
		return inv
	case tool == "go" && inv.sub == "mod":
		inv.install = len(rest) > 0 && (rest[0] == "tidy" || rest[0] == "download")
		return inv
	case tool == "go" && inv.sub != "get" && inv.sub != "install":
		inv.install = installSubs["go"][inv.sub] // build/run/test fetch missing modules from go.mod
		return inv
	case tool == "cargo" && inv.sub == "install":
		inv.global = true
	}
	inv.install = installSubs[tool][inv.sub]
	if inv.install && (inv.sub != "run" && inv.sub != "test" && inv.sub != "build") {
		for _, s := range rest {
			if !isLocalSpec(s) {
				inv.specs = append(inv.specs, s)
			}
		}
	}
	return inv
}

// isLocalSpec: paths, archives and VCS URLs are not registry packages.
func isLocalSpec(s string) bool {
	return strings.HasPrefix(s, ".") || strings.HasPrefix(s, "/") || strings.Contains(s, "://") ||
		strings.HasPrefix(s, "git+") || strings.HasPrefix(s, "file:") || filepath.Ext(s) == ".tgz" ||
		filepath.Ext(s) == ".whl" || strings.HasSuffix(s, ".tar.gz")
}

// pinned returns (name, version) when a spec names one exact version.
func pinned(tool, spec string) (name, version string, ok bool) {
	switch tool {
	case "npm", "pnpm", "yarn":
		at := strings.LastIndex(spec, "@")
		if at <= 0 {
			return "", "", false
		}
		name, version = spec[:at], spec[at+1:]
	case "pip", "uv", "poetry":
		var found bool
		name, version, found = strings.Cut(spec, "==")
		if !found {
			return "", "", false
		}
		if i := strings.IndexAny(name, "["); i >= 0 {
			name = name[:i]
		}
	case "go", "cargo":
		var found bool
		name, version, found = strings.Cut(spec, "@")
		if !found {
			return "", "", false
		}
	}
	if version == "" || strings.ContainsAny(version, "^~<>=*| ,") || version == "latest" || strings.HasPrefix(version, "next") {
		return "", "", false
	}
	return strings.TrimSpace(name), strings.TrimSpace(version), true
}

var toolEcosystem = map[string]string{"npm": "npm", "pnpm": "npm", "yarn": "npm", "pip": "pypi", "uv": "pypi", "poetry": "pypi", "go": "go", "cargo": "cargo"}
