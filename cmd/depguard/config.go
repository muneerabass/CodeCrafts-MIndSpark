package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// defaultAPIURL is set at build time (-ldflags "-X main.defaultAPIURL=...").
var defaultAPIURL = ""

const projectFile = ".depguard.yml"

// credentials are per user, never per repository.
type credentials struct {
	APIURL string `json:"api_url"`
	APIKey string `json:"api_key"`
}

func configDir() string {
	if d := os.Getenv("DEPGUARD_CONFIG_DIR"); d != "" {
		return d
	}
	d, err := os.UserConfigDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "depguard")
}

func credentialsPath() string { return filepath.Join(configDir(), "credentials.json") }

func loadCredentials() credentials {
	var c credentials
	if b, err := os.ReadFile(credentialsPath()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func saveCredentials(c credentials) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFileAtomic(credentialsPath(), b, 0o600)
}

// rule mirrors the server's package rule (scan.PackageRule).
type rule struct {
	Ecosystem string `yaml:"ecosystem,omitempty" json:"ecosystem,omitempty"`
	Name      string `yaml:"name" json:"name"`
	Versions  string `yaml:"versions,omitempty" json:"versions,omitempty"`
	Deny      bool   `yaml:"deny,omitempty" json:"deny,omitempty"`
	Allow     bool   `yaml:"allow,omitempty" json:"allow,omitempty"`
	Reason    string `yaml:"reason,omitempty" json:"reason,omitempty"`
	Severity  string `yaml:"severity,omitempty" json:"severity,omitempty"`
}

// projectConfig is .depguard.yml, committed to the repository.
type projectConfig struct {
	Project    string   `yaml:"project"`
	APIURL     string   `yaml:"api_url,omitempty"` // only honoured when it matches the configured API
	Ecosystems []string `yaml:"ecosystems,omitempty"`
	FailClosed bool     `yaml:"fail_closed"`
	Rules      []rule   `yaml:"rules"`

	dir string // directory holding the file
}

// findProject walks up from dir to the nearest .depguard.yml (nil if none),
// stopping at the git root or the home directory.
func findProject(dir string) (*projectConfig, error) {
	dir, _ = filepath.Abs(dir)
	for {
		p := filepath.Join(dir, projectFile)
		if b, err := os.ReadFile(p); err == nil {
			var pc projectConfig
			if err := yaml.Unmarshal(b, &pc); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			pc.dir = dir
			return &pc, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir || repoBoundary(dir) {
			return nil, nil
		}
		dir = parent
	}
}

// repoBoundary: files above a git root or the home directory belong to someone else.
func repoBoundary(dir string) bool {
	home, _ := os.UserHomeDir()
	return exists(filepath.Join(dir, ".git")) || (home != "" && filepath.Clean(home) == dir)
}

// resolveClient picks credentials: flags > env > saved login > build default.
// A repository's .depguard.yml api_url is never trusted with the key: it only
// matters when it matches a URL the user configured.
func resolveClient(flagURL, flagKey string, pc *projectConfig) (*client, error) {
	saved := loadCredentials()
	env := os.Getenv("DEPGUARD_API_URL")
	url := firstNonEmpty(flagURL, env, saved.APIURL, defaultAPIURL)
	key := firstNonEmpty(flagKey, os.Getenv("DEPGUARD_API_KEY"), saved.APIKey)
	if pc != nil && pc.APIURL != "" {
		u := strings.TrimRight(pc.APIURL, "/")
		if u != strings.TrimRight(saved.APIURL, "/") && u != strings.TrimRight(env, "/") && u != strings.TrimRight(defaultAPIURL, "/") {
			fmt.Fprintf(out, "%s %s\n", brand(), yellow("! ignoring api_url "+pc.APIURL+" from "+projectFile+": not your configured API (use depguard login --api-url)"))
		}
	}
	if key == "" {
		return nil, errNotLoggedIn
	}
	if url == "" {
		return nil, errors.New("no API URL: run `depguard login --api-url https://api.example.com`")
	}
	return newClient(url, key)
}

var errNotLoggedIn = errors.New("not logged in: run `depguard login` (API key from Settings → API Keys)")

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after the rename
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
