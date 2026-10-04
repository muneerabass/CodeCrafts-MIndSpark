package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Install interception: small shims named after each package manager live in
// ~/.depguard/bin, which is put first on PATH. Every install (typed, from an
// IDE terminal, a Makefile or a script) runs `depguard <tool> ...` first.

const (
	markStart = "# >>> depguard install guard >>>"
	markEnd   = "# <<< depguard install guard <<<"
)

func shimDir() string {
	if d := os.Getenv("DEPGUARD_SHIM_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".depguard", "bin")
}

func runSetup(args []string) error {
	if len(args) > 0 && args[0] == "agents" {
		return runSetupAgents(args[1:])
	}
	if len(args) == 0 || args[0] != "shell" {
		return fmt.Errorf("usage: depguard setup shell [--remove] | depguard setup agents [--remove|--print]")
	}
	fs := flag.NewFlagSet("setup shell", flag.ExitOnError)
	remove := fs.Bool("remove", false, "remove the shims and PATH changes")
	_ = fs.Parse(args[1:])
	if *remove {
		return removeShell()
	}
	return installShell()
}

func installShell() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	dir := shimDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Shims only for tools installed now; `depguard setup shell` again picks up new ones.
	var shimmed []string
	for _, t := range guardedTools {
		path := filepath.Join(dir, t)
		body := fmt.Sprintf("#!/bin/sh\n# depguard install guard: checks installs, then runs the real %s.\nDG=%q\n[ -x \"$DG\" ] || DG=depguard\n"+
			"DEPGUARD_SHIM_DEPTH=$((${DEPGUARD_SHIM_DEPTH:-0}+1)); export DEPGUARD_SHIM_DEPTH\nexec \"$DG\" %s \"$@\"\n", t, self, t)
		if runtime.GOOS == "windows" {
			path += ".cmd"
			body = fmt.Sprintf("@echo off\r\nrem depguard install guard: checks installs, then runs the real %s.\r\nsetlocal\r\n"+
				"set /a DEPGUARD_SHIM_DEPTH=DEPGUARD_SHIM_DEPTH+1 >nul\r\n\"%s\" %s %%*\r\n", t, self, t)
		}
		if _, err := realTool(t); err != nil {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			return err
		}
		shimmed = append(shimmed, t)
	}
	var changed []string
	for _, rc := range rcFiles(true) {
		ok, err := addBlock(rc.path, rc.block(dir))
		if err != nil {
			return err
		}
		if ok {
			changed = append(changed, rc.path)
		}
	}
	fmt.Fprintf(out, "%s %s installed for %s\n", brand(), green("✔ install guard"), bold(firstNonEmpty(strings.Join(shimmed, ", "), "no package managers found on PATH")))
	fmt.Fprintf(out, "  shims: %s\n", dim(dir))
	for _, c := range changed {
		fmt.Fprintf(out, "  PATH updated in %s\n", dim(c))
	}
	fmt.Fprintf(out, "\n  %s open a new terminal (or run: %s) then try %s\n\n", cyan("next:"),
		bold(activateHint(dir)), bold("npm install <package>"))
	return nil
}

func activateHint(dir string) string {
	if runtime.GOOS == "windows" {
		return `$env:PATH = "` + dir + `;" + $env:PATH`
	}
	return `export PATH="` + dir + `:$PATH"`
}

func removeShell() error {
	for _, rc := range rcFiles(false) {
		if err := removeBlock(rc.path); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(shimDir()); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s %s (open a new terminal)\n", brand(), green("✔ install guard removed"))
	return nil
}

type rcFile struct {
	path string
	kind string // sh | fish | ps
}

func (r rcFile) block(dir string) string {
	switch r.kind {
	case "fish":
		return fmt.Sprintf("%s\nfish_add_path -p %q\n%s\n", markStart, dir, markEnd)
	case "ps":
		return fmt.Sprintf("%s\n$env:PATH = \"%s;\" + $env:PATH\n%s\n", markStart, dir, markEnd)
	}
	return fmt.Sprintf("%s\ncase \":$PATH:\" in *\":%s:\"*) ;; *) export PATH=\"%s:$PATH\" ;; esac\n%s\n", markStart, dir, dir, markEnd)
}

// rcFiles lists the shell startup files to change: existing ones, plus the
// file for the user's login shell (created when install is true).
func rcFiles(install bool) []rcFile {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		docs := filepath.Join(home, "Documents")
		return []rcFile{{filepath.Join(docs, "PowerShell", "Microsoft.PowerShell_profile.ps1"), "ps"},
			{filepath.Join(docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"), "ps"}}
	}
	shell := filepath.Base(os.Getenv("SHELL"))
	cands := []struct {
		rc    rcFile
		owner string
	}{
		{rcFile{filepath.Join(home, ".bashrc"), "sh"}, "bash"},
		{rcFile{filepath.Join(home, ".zshrc"), "sh"}, "zsh"},
		{rcFile{filepath.Join(home, ".profile"), "sh"}, ""},
		{rcFile{filepath.Join(home, ".config", "fish", "conf.d", "depguard.fish"), "fish"}, "fish"},
	}
	var out []rcFile
	for _, c := range cands {
		if exists(c.rc.path) || (install && c.owner == shell) || (install && c.owner == "" && shell != "fish") {
			out = append(out, c.rc)
		}
	}
	return out
}

// addBlock appends the guarded block once; it reports whether the file changed.
func addBlock(path, block string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if strings.Contains(string(b), markStart) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	s := string(b)
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return true, os.WriteFile(path, []byte(s+"\n"+block), 0o644)
}

func removeBlock(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	s := string(b)
	i := strings.Index(s, markStart)
	j := strings.Index(s, markEnd)
	if i < 0 || j < i {
		return nil
	}
	s = strings.TrimRight(s[:i], "\n") + "\n" + strings.TrimLeft(s[j+len(markEnd):], "\n")
	return os.WriteFile(path, []byte(s), 0o644)
}

// runDoctor reports whether installs on this machine are guarded.
func runDoctor() error {
	cwd, _ := os.Getwd()
	pc, perr := findProject(cwd)
	saved := loadCredentials()
	ok := func(b bool, good, bad string) {
		if b {
			fmt.Fprintf(out, "  %s %s\n", green("✔"), good)
		} else {
			fmt.Fprintf(out, "  %s %s\n", red("✖"), bad)
		}
	}
	fmt.Fprintf(out, "%s doctor\n\n", brand())
	c, err := resolveClient("", "", pc)
	ok(err == nil, "logged in ("+firstNonEmpty(os.Getenv("DEPGUARD_API_URL"), saved.APIURL, defaultAPIURL)+")", "not logged in: run depguard login")
	if err == nil {
		var me map[string]any
		_, e := c.do("GET", "/v1/me", "", nil, &me)
		ok(e == nil, fmt.Sprintf("API reachable, team %v, block mode %v", me["domain"], me["block_mode"]), "API not reachable: "+firstLine(fmt.Sprint(e)))
	}
	switch {
	case perr != nil:
		ok(false, "", perr.Error())
	case pc != nil:
		ok(true, fmt.Sprintf("project %s (%s, %d repo rules)", pc.Project, filepath.Join(pc.dir, projectFile), len(pc.Rules)), "")
	default:
		fmt.Fprintf(out, "  %s %s\n", yellow("•"), "no .depguard.yml here (team policy still applies): run depguard init")
	}
	dir := shimDir()
	onPath := false
	if dfi, err := os.Stat(dir); err == nil {
		for _, d := range filepath.SplitList(os.Getenv("PATH")) {
			if fi, err := os.Stat(d); err == nil && os.SameFile(fi, dfi) {
				onPath = true
				break
			}
		}
	}
	ok(exists(dir), "shims installed in "+dir, "shims not installed: run depguard setup shell")
	ok(onPath, "shims are on PATH", "shims are not on PATH in this terminal: open a new terminal")
	for _, t := range guardedTools {
		bin, err := realTool(t)
		if err != nil {
			continue
		}
		// What the shell runs for t: the shim, unless another dir (nvm, pyenv, mise, volta) comes first.
		first, _ := exec.LookPath(t)
		switch {
		case first == "" || !isShim(first):
			fmt.Fprintf(out, "    %s %-7s → %s %s\n", red("✖"), t, dim(bin), red("not guarded: "+firstNonEmpty(first, t)+" runs first (run depguard setup shell, open a new terminal)"))
		default:
			fmt.Fprintf(out, "    %s %-7s → %s\n", green("•"), t, dim(bin))
		}
	}
	fmt.Fprintln(out)
	return nil
}
