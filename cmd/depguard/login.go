package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

func prompt(q, def string) string {
	if def != "" {
		fmt.Fprintf(out, "%s %s %s ", cyan("?"), q, dim("("+def+")"))
	} else {
		fmt.Fprintf(out, "%s %s ", cyan("?"), q)
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if line = strings.TrimSpace(line); line == "" {
		return def
	}
	return line
}

func interactive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// runLogin verifies an API key and stores it for this user.
func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	saved := loadCredentials()
	apiURL := fs.String("api-url", firstNonEmpty(os.Getenv("DEPGUARD_API_URL"), saved.APIURL, defaultAPIURL), "API base URL")
	apiKey := fs.String("api-key", os.Getenv("DEPGUARD_API_KEY"), "API key (dg_...) from Settings → API Keys")
	_ = fs.Parse(args)
	_, err := login(*apiURL, *apiKey)
	return err
}

func login(apiURL, apiKey string) (map[string]any, error) {
	if apiURL == "" && interactive() {
		apiURL = prompt("depguard API URL:", "")
	}
	if apiKey == "" && interactive() {
		apiKey = prompt("API key (Settings → API Keys):", "")
	}
	if apiURL == "" || apiKey == "" {
		return nil, fmt.Errorf("--api-url and --api-key are required")
	}
	c, err := newClient(apiURL, apiKey)
	if err != nil {
		return nil, err
	}
	var me map[string]any
	if _, err := c.do("GET", "/v1/me", "", nil, &me); err != nil {
		return nil, fmt.Errorf("could not verify the API key: %w", err)
	}
	if err := saveCredentials(credentials{APIURL: strings.TrimRight(apiURL, "/"), APIKey: apiKey}); err != nil {
		return nil, err
	}
	_ = os.Remove(guardStatePath()) // clean-check cache and endpoint id belong to the previous login
	fmt.Fprintf(out, "%s %s to %s %s\n", brand(), green("✔ logged in"), bold(fmt.Sprint(me["domain"])), dim("("+credentialsPath()+")"))
	return me, nil
}

func runLogout() error {
	if err := os.Remove(credentialsPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Fprintf(out, "%s %s\n", brand(), green("✔ logged out"))
	return nil
}

// runInit links the current project: writes .depguard.yml and offers the shell setup.
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	project := fs.String("project", "", "project name (default: git remote owner/repo or folder name)")
	force := fs.Bool("force", false, "overwrite an existing .depguard.yml")
	shell := fs.Bool("shell", true, "set up the install guard shims for this user")
	apiURL, apiKey := addClientFlags(fs)
	_ = fs.Parse(args)

	cwd, _ := os.Getwd()
	path := filepath.Join(cwd, projectFile)
	if exists(path) && !*force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", projectFile)
	}
	fmt.Fprintf(out, "\n%s %s\n\n", brand(), bold("init"))
	c, err := resolveClient(*apiURL, *apiKey, nil)
	var me map[string]any
	if err == nil {
		_, err = c.do("GET", "/v1/me", "", nil, &me)
	}
	if err != nil {
		if me, err = login(*apiURL, *apiKey); err != nil {
			return err
		}
	}
	ecos := detectEcosystems(cwd)
	name := firstNonEmpty(*project, gitProject(cwd), filepath.Base(cwd))
	pc := projectConfig{Project: name, Ecosystems: ecos, Rules: []rule{}}
	b, _ := yaml.Marshal(pc)
	content := "# depguard install guard — checked before every npm/pip/go/cargo install.\n" +
		"# Team policy (dashboard → Policy) always applies; rules here can only make it stricter.\n" +
		strings.Replace(string(b), "rules: []\n", "rules:\n"+
			"  # Uncomment or add rules. versions = allowed range; severity high (default) blocks, medium/low warn.\n"+
			"  # - { ecosystem: npm, name: lodash, versions: \">=4.17.21\", reason: \"prototype pollution fixes\" }\n"+
			"  # - { ecosystem: npm, name: moment, versions: \"<3\", severity: medium }\n"+
			"  # - { name: request, deny: true, reason: \"deprecated, use undici\" }\n"+
			"  # - { ecosystem: pypi, name: django, versions: \">=4.2 <6\" }\n", 1)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	pol, _ := me["policy"].(map[string]any)
	fmt.Fprintf(out, "  %s wrote %s for project %s\n", green("✔"), bold(projectFile), bold(name))
	fmt.Fprintf(out, "  %s ecosystems: %s\n", green("✔"), firstNonEmpty(strings.Join(ecos, ", "), "none detected yet"))
	fmt.Fprintf(out, "  %s team %s · block mode %s · vulnerabilities ≥ %v · %v package rules\n", green("✔"), bold(fmt.Sprint(me["domain"])),
		bold(map[bool]string{true: "on", false: "off"}[me["block_mode"] == true]), pol["vulnerability_min_risk"], pol["package_rules"])
	if *shell {
		fmt.Fprintln(out)
		if err := installShell(); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "  Commit %s so your team shares the same repo rules. In CI run %s.\n\n", bold(projectFile), bold("depguard check"))
	return nil
}

func detectEcosystems(dir string) []string {
	var out []string
	add := func(eco string, files ...string) {
		for _, f := range files {
			if exists(filepath.Join(dir, f)) {
				out = append(out, eco)
				return
			}
		}
	}
	add("npm", "package.json")
	add("pypi", "pyproject.toml", "requirements.txt", "Pipfile", "setup.py")
	add("go", "go.mod")
	add("cargo", "Cargo.toml")
	return out
}

// gitProject is owner/repo from the origin remote.
func gitProject(dir string) string {
	b, err := runTool(dir, "git", []string{"remote", "get-url", "origin"}, nil)
	if err != nil {
		return ""
	}
	u := strings.TrimSuffix(strings.TrimSpace(string(b)), ".git")
	u = strings.ReplaceAll(u, ":", "/")
	parts := strings.Split(u, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2] + "/" + parts[len(parts)-1]
}
