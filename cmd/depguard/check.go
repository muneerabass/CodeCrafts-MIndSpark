package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// runCheck checks the project's current lockfiles without installing (CI, git hooks).
func runCheck(args []string) (int, error) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	dir := fs.String("dir", ".", "project directory")
	failOn := fs.String("fail-on", "block", "exit 1 on: block | warn | never")
	jsonOut := fs.Bool("json", false, "print the result as JSON")
	apiURL, apiKey := addClientFlags(fs)
	_ = fs.Parse(args)

	root, _ := filepath.Abs(*dir)
	pc, err := findProject(root)
	if err != nil {
		return 2, err
	}
	c, err := resolveClient(*apiURL, *apiKey, pc)
	if err != nil {
		return 2, err
	}
	files, err := findLockfiles(root)
	if err != nil {
		return 2, err
	}
	var req checkRequest
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			return 2, err
		}
		cf := checkFile{f, string(b)}
		if manifestNames[filepath.Base(f)] {
			req.Manifests = append(req.Manifests, cf)
		}
		if lockfileNames[filepath.Base(f)] {
			req.After = append(req.After, cf)
		}
	}
	if len(req.After) == 0 {
		return 2, fmt.Errorf("no lockfiles found in %s", root)
	}
	if pc != nil {
		req.RepoRules = pc.Rules
	}
	start := time.Now()
	sp := startSpinner(fmt.Sprintf("checking %s…", plural(len(req.After), "lockfile", "lockfiles")))
	var result checkResult
	_, err = c.do("POST", "/v1/packages/check", "", req, &result)
	sp.end()
	if err != nil {
		return 2, err
	}
	if *jsonOut {
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
	} else {
		printReport(result, &resolution{}, invocation{tool: "check", sub: filepath.Base(root)}, time.Since(start))
	}
	switch {
	case *failOn == "warn" && result.Decision != "allow":
		return 1, nil
	case *failOn == "block" && result.Decision == "block":
		return 1, nil
	}
	return 0, nil
}
