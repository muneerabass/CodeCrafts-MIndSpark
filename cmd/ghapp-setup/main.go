// Command ghapp-setup registers the depguard GitHub App via GitHub's manifest
// flow and writes its credentials for deploy/.env.
//
//	go run ./cmd/ghapp-setup -app-url https://app.example.com -api-url https://api.example.com [-org my-org]
//
// It serves a local page that posts the manifest to GitHub; after you confirm,
// GitHub redirects back with a code that is exchanged for the app id, private
// key, webhook secret and OAuth client credentials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-github/v92/github"
)

type manifest struct {
	Name               string            `json:"name"`
	URL                string            `json:"url"`
	Description        string            `json:"description"`
	HookAttributes     map[string]any    `json:"hook_attributes"`
	RedirectURL        string            `json:"redirect_url"`
	CallbackURLs       []string          `json:"callback_urls"`
	SetupURL           string            `json:"setup_url"`
	Public             bool              `json:"public"`
	DefaultPermissions map[string]string `json:"default_permissions"`
	DefaultEvents      []string          `json:"default_events"`
}

var page = template.Must(template.New("p").Parse(`<!doctype html><meta charset="utf-8">
<title>Create GitHub App</title>
<form id="f" method="post" action="{{.Action}}">
<input type="hidden" name="manifest" value="{{.Manifest}}">
<p>Redirecting to GitHub… <button type="submit">Continue</button></p>
</form><script>document.getElementById("f").submit()</script>`))

func main() {
	name := flag.String("name", "depguard", "GitHub App name (must be globally unique)")
	appURL := flag.String("app-url", "", "public web URL, e.g. https://app.example.com (required)")
	apiURL := flag.String("api-url", "", "public API URL receiving webhooks, e.g. https://api.example.com (required)")
	org := flag.String("org", "", "create the app under this organization instead of your user")
	public := flag.Bool("public", true, "allow installation on any account (unlinked installs stay pending)")
	out := flag.String("out", "deploy/secrets", "directory for github-app.pem")
	listen := flag.String("listen", "127.0.0.1:3999", "local address for the setup page")
	flag.Parse()
	if *appURL == "" || *apiURL == "" {
		flag.Usage()
		os.Exit(2)
	}

	local := "http://" + *listen
	m := manifest{
		Name:           *name,
		URL:            *appURL,
		Description:    "Supply chain security checks for pull requests: malicious packages, vulnerabilities and risky licenses.",
		HookAttributes: map[string]any{"url": *apiURL + "/github/webhook", "active": true},
		RedirectURL:    local + "/callback",
		CallbackURLs:   []string{*appURL + "/api/auth/callback/github"},
		SetupURL:       *appURL + "/setup/integrations",
		Public:         *public,
		DefaultPermissions: map[string]string{
			"contents":        "read",
			"pull_requests":   "read",
			"checks":          "write",
			"issues":          "write",
			"metadata":        "read",
			"email_addresses": "read",
		},
		DefaultEvents: []string{"pull_request", "push", "check_run"},
	}
	mj, err := json.Marshal(m)
	if err != nil {
		log.Fatal(err)
	}
	action := "https://github.com/settings/apps/new"
	if *org != "" {
		action = fmt.Sprintf("https://github.com/organizations/%s/settings/apps/new", *org)
	}

	done := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		_ = page.Execute(w, map[string]string{"Action": action, "Manifest": string(mj)})
	})
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		cfg, err := complete(r.Context(), code, *out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			done <- err
			return
		}
		fmt.Fprintf(w, "GitHub App %q created. Return to the terminal.", cfg.GetSlug())
		done <- nil
	})

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fmt.Printf("Open %s in your browser to create the GitHub App.\n", local)
	if err := <-done; err != nil {
		log.Fatal(err)
	}
	_ = srv.Shutdown(context.Background())
}

// complete exchanges the manifest code and writes the private key + env lines.
func complete(ctx context.Context, code, outDir string) (*github.AppConfig, error) {
	gh, err := github.NewClient(nil)
	if err != nil {
		return nil, err
	}
	cfg, _, err := gh.Apps.CompleteAppManifest(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange manifest code: %w", err)
	}
	if cfg.GetPEM() == "" {
		return nil, errors.New("GitHub returned no private key")
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	pemPath := filepath.Join(outDir, "github-app.pem")
	if err := os.WriteFile(pemPath, []byte(cfg.GetPEM()), 0o600); err != nil {
		return nil, err
	}
	fmt.Printf(`
GitHub App created: %s
Private key written to %s
Add these to deploy/.env:

GITHUB_APP_ID=%d
GITHUB_APP_SLUG=%s
GITHUB_WEBHOOK_SECRET=%s
GITHUB_CLIENT_ID=%s
GITHUB_CLIENT_SECRET=%s
GITHUB_APP_PRIVATE_KEY_FILE=./secrets/github-app.pem
`, cfg.GetHTMLURL(), pemPath, cfg.GetID(), cfg.GetSlug(), cfg.GetWebhookSecret(), cfg.GetClientID(), cfg.GetClientSecret())
	return cfg, nil
}
