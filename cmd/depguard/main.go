// Command depguard is the depguard CLI:
//
//	depguard login / init / setup shell   connect this machine and project, guard installs
//	depguard npm|npx|pnpm|yarn|pip|uv|uvx|poetry|go|cargo ...   check an install, then run it
//	depguard check   check the project's lockfiles (CI, git hooks)
//	depguard scan    upload lockfiles for a full scan (GitHub Actions, GitLab CI, ...)
//	depguard agent   endpoint agent: check-in, AI tooling inventory, pmg and gryph events
//
// Configuration: `depguard login`, or DEPGUARD_API_URL and DEPGUARD_API_KEY.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// Guarded install: `depguard [--force --reason r --dry-run --json] <tool> args...`
	if o, rest, err := parseGuardFlags(os.Args[1:]); err == nil && len(rest) > 0 && isGuardedTool(rest[0]) {
		os.Exit(runGuard(o, rest[0], rest[1:]))
	} else if err != nil && strings.HasPrefix(os.Args[1], "--") && os.Args[1] != "--version" && os.Args[1] != "--help" {
		fmt.Fprintln(os.Stderr, "depguard:", err)
		os.Exit(2)
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "login":
		err = runLogin(os.Args[2:])
	case "logout":
		err = runLogout()
	case "init":
		err = runInit(os.Args[2:])
	case "setup":
		err = runSetup(os.Args[2:])
	case "doctor":
		err = runDoctor()
	case "check":
		code, err = runCheck(os.Args[2:])
	case "scan":
		code, err = runScan(os.Args[2:])
	case "agent":
		err = runAgent(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return
	case "help", "--help", "-h":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %s\n", brand(), red(err.Error()))
		os.Exit(2)
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s — supply chain security for your dependencies

%s
  depguard login            connect to your team (API key from Settings → API Keys)
  depguard init             link this project (.depguard.yml) and guard installs
  depguard setup shell      guard npm, npx, pnpm, yarn, pip, uv, uvx, poetry, go and cargo on this machine
  depguard setup agents     connect Claude Code, Cursor, VS Code, Windsurf, Gemini CLI and Codex (MCP + skill)
  depguard doctor           show whether installs on this machine are guarded

%s
  npm install express       with the guard set up, installs are checked first: vulnerabilities,
  pip install requests      malware, banned packages, allowed versions and your team's policy
  go get golang.org/x/net   (or run explicitly: depguard npm install express)

  depguard --force --reason "why" npm install x    install despite blocking findings (logged)
  depguard --dry-run npm install x                 check only, do not install

%s
  depguard check            check the project's lockfiles (exit 1 when blocked)
  depguard scan             upload lockfiles for a full scan and report
  depguard agent            run the endpoint agent (inventory, pmg/gryph events)

environment: DEPGUARD_API_URL, DEPGUARD_API_KEY, DEPGUARD_DISABLE=1 (skip checks), NO_COLOR
`, brand(), bold("Setup"), bold("Guarded installs"), bold("CI and scans"))
}

// client talks to the machine API.
type client struct {
	base, key string
	http      *http.Client
}

func addClientFlags(fs *flag.FlagSet) (*string, *string) {
	return fs.String("api-url", os.Getenv("DEPGUARD_API_URL"), "API base URL (env DEPGUARD_API_URL)"),
		fs.String("api-key", os.Getenv("DEPGUARD_API_KEY"), "API key dg_... (env DEPGUARD_API_KEY)")
}

func newClient(base, key string) (*client, error) {
	if base == "" || key == "" {
		return nil, errors.New("DEPGUARD_API_URL and DEPGUARD_API_KEY (or --api-url/--api-key) are required")
	}
	return &client{base: strings.TrimRight(base, "/"), key: key, http: &http.Client{Timeout: 3 * time.Minute}}, nil
}

// do sends body (JSON-encoded unless it is an io.Reader) and decodes a JSON reply into out
// (a *[]byte out receives the raw body).
func (c *client) do(method, path, contentType string, body any, out any) (int, error) {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case io.Reader:
		rd = b
	default:
		j, err := json.Marshal(b)
		if err != nil {
			return 0, err
		}
		rd, contentType = bytes.NewReader(j), "application/json"
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("User-Agent", "depguard-cli/"+version)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if res.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
		}
		return res.StatusCode, fmt.Errorf("%s %s: %d %s", method, path, res.StatusCode, e.Error)
	}
	if b, ok := out.(*[]byte); ok {
		*b = raw
		return res.StatusCode, nil
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return res.StatusCode, fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return res.StatusCode, nil
}
