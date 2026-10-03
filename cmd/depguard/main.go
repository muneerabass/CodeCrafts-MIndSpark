// Command depguard is the depguard CLI:
//
//	depguard scan   upload lockfiles for a scan (local use, GitHub Actions, GitLab CI, Bitbucket Pipelines)
//	depguard agent  endpoint agent: check-in, AI tooling inventory, pmg and gryph event shipping
//
// Configuration: DEPGUARD_API_URL and DEPGUARD_API_KEY (or --api-url / --api-key).
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
	var err error
	switch os.Args[1] {
	case "scan":
		var code int
		code, err = runScan(os.Args[2:])
		if err == nil {
			os.Exit(code)
		}
	case "agent":
		err = runAgent(os.Args[2:])
	case "version", "--version":
		fmt.Println(version)
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "depguard:", err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: depguard <command> [flags]

commands:
  scan    find lockfiles and scan them (exit 1 on policy failure with --fail-on-violation)
  agent   run the endpoint agent (check-in, inventory, pmg/gryph events)
  version print version

environment: DEPGUARD_API_URL, DEPGUARD_API_KEY`)
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

// do sends body (JSON-encoded unless it is an io.Reader) and decodes a JSON reply into out.
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
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return res.StatusCode, fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return res.StatusCode, nil
}
