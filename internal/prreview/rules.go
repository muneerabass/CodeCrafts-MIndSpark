// Package prreview is the rule-based security review of a pull request diff
// and its labels. It always runs (no AI needed), is precise rather than
// exhaustive, and its findings use the same shape as the AI review.
package prreview

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/depguard/depguard/internal/render"
)

// File is one changed file of a PR with its unified diff patch.
type File struct {
	Path      string
	Status    string // added | modified | removed | renamed
	Patch     string // GitHub's per-file patch; empty for binary or very large files
	Additions int
	Deletions int
}

// AddedLine is a line added by the PR, with its line number in the new file.
type AddedLine struct {
	Line int
	Text string
}

var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// AddedLines parses a unified diff patch into the added lines of the new file.
func AddedLines(patch string) []AddedLine {
	var out []AddedLine
	n := 0
	for _, l := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(l, "@@"):
			if m := hunkRe.FindStringSubmatch(l); m != nil {
				n, _ = strconv.Atoi(m[1])
			}
		case strings.HasPrefix(l, "+"):
			out = append(out, AddedLine{n, l[1:]})
			n++
		case strings.HasPrefix(l, "-"):
		case strings.HasPrefix(l, `\`): // "\ No newline at end of file"
		default:
			n++
		}
	}
	return out
}

type rule struct {
	id, severity, category, title, explanation, suggestion string
	re                                                     *regexp.Regexp
	files                                                  func(p string) bool // nil = source files
	skip                                                   *regexp.Regexp      // a match here clears the finding (e.g. safe variant)
}

func ext(p string) string { return strings.ToLower(path.Ext(p)) }

var sourceExt = map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".py": true,
	".go": true, ".java": true, ".kt": true, ".rb": true, ".php": true, ".cs": true, ".rs": true, ".scala": true, ".swift": true,
	".vue": true, ".svelte": true}

func isSource(p string) bool { return sourceExt[ext(p)] }
func isWorkflow(p string) bool {
	return strings.HasPrefix(p, ".github/workflows/") && (ext(p) == ".yml" || ext(p) == ".yaml")
}
func anyText(p string) bool {
	switch ext(p) {
	case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".lock", ".sum":
		return false
	}
	return !isLockfile(p)
}

// Rules are security checks with a low false-positive rate. Secrets apply to
// every text file; the rest to source code or workflows.
var rules = []rule{
	{id: "secret-aws-key", severity: "critical", category: "secrets", title: "AWS access key committed",
		explanation: "An AWS access key id is in the diff; anyone with repository access can use it.",
		suggestion:  "Rotate the key in AWS IAM now (deleting it from the PR does not remove it from git history), then load credentials from the environment or a secret manager.",
		re:          regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), files: anyText},
	{id: "secret-private-key", severity: "critical", category: "secrets", title: "Private key committed",
		explanation: "A private key block is in the diff.", suggestion: "Revoke the key now (it stays in git history even if removed), and store keys outside the repository.",
		re: regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), files: anyText},
	{id: "secret-token", severity: "critical", category: "secrets", title: "API token committed",
		explanation: "A token for GitHub, GitLab, npm, Slack, Stripe, SendGrid, Twilio, Google, OpenAI or Anthropic is in the diff.",
		suggestion:  "Revoke the token now (it stays in git history even if removed), and read it from an environment variable or secret manager.",
		re:          regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}|glpat-[A-Za-z0-9_\-]{20,}|npm_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|[sr]k_live_[A-Za-z0-9]{20,}|SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|SK[0-9a-f]{32}|AIza[0-9A-Za-z_\-]{35}|sk-ant-[A-Za-z0-9_\-]{20,}|sk-(proj-)?[A-Za-z0-9]{32,}|dg_[A-Za-z0-9]{32})\b|https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,}`),
		files:       anyText},
	{id: "secret-cloud-credential", severity: "critical", category: "secrets", title: "Cloud credential committed",
		explanation: "An Azure storage account key or a Google Cloud service account key is in the diff.",
		suggestion:  "Rotate the credential now (it stays in git history even if removed), and use workload identity or a secret manager.",
		re:          regexp.MustCompile(`AccountKey=[A-Za-z0-9+/]{80,}={0,2}|"private_key_id"\s*:\s*"[0-9a-f]{40}"`), files: anyText},
	{id: "secret-hardcoded-password", severity: "high", category: "secrets", title: "Hard-coded password or secret",
		explanation: "A password, secret or API key is assigned a literal value.",
		suggestion:  "Read it from configuration or a secret manager instead of the source code.",
		re:          regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api_?key|access_?token|client_?secret)\b["']?\s*[:=]\s*["'][^"'\s$<{]{8,}["']`),
		skip:        regexp.MustCompile(`(?i)(example|placeholder|changeme|dummy|your[_-]|xxx|\*\*\*|test|sample|process\.env|os\.environ|getenv)`)},
	{id: "sql-injection", severity: "high", category: "injection", title: "SQL query built from untrusted input",
		explanation: "The query string is assembled with concatenation or interpolation, which allows SQL injection.",
		suggestion:  "Use parameterized queries (placeholders such as ? or $1) and pass values separately.",
		re:          regexp.MustCompile(`(?i)\b(query|execute|exec|raw|prepare|cursor\.execute|db\.(query|exec))\s*\(\s*(f["']|["'][^"']*\b(select|insert|update|delete|where)\b[^"']*["']\s*(\+|%|\.format)|` + "`" + `[^` + "`" + `]*\b(select|insert|update|delete|where)\b[^` + "`" + `]*\$\{)`)},
	{id: "command-injection", severity: "high", category: "injection", title: "Shell command built from input",
		explanation: "A shell command is run with string concatenation or interpolation, which allows command injection.",
		suggestion:  "Pass arguments as a list without a shell (execFile/spawn, subprocess.run([...]), exec.Command(name, args...)).",
		re:          regexp.MustCompile(`(?i)(child_process\.)?\bexec(Sync)?\s*\(\s*(` + "`" + `[^` + "`" + `]*\$\{|["'][^"']*["']\s*\+)|subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\s*\(\s*(f["']|[^"')]*\+)`)},
	{id: "code-eval", severity: "high", category: "injection", title: "Dynamic code execution",
		explanation: "eval / new Function / exec runs code that may come from user input.",
		suggestion:  "Avoid evaluating strings as code; parse data with a safe parser instead.",
		re:          regexp.MustCompile(`(^|[^\w.])(eval|exec)\s*\(\s*[^"'\s)]|new Function\s*\(`),
		skip:        regexp.MustCompile(`(?i)\.exec\(|regex|re\.exec|execSync|execFile|// *safe`)},
	{id: "unsafe-deserialization", severity: "high", category: "deserialization", title: "Unsafe deserialization",
		explanation: "Deserializing untrusted data with pickle, yaml.load or similar can execute code.",
		suggestion:  "Use yaml.safe_load / json, or verify the data's origin before deserializing.",
		re:          regexp.MustCompile(`pickle\.loads?\s*\(|yaml\.load\s*\(|marshal\.loads\s*\(|ObjectInputStream\s*\(|unserialize\s*\(`),
		skip:        regexp.MustCompile(`SafeLoader|CSafeLoader`)},
	{id: "tls-verification-disabled", severity: "high", category: "crypto", title: "TLS certificate verification disabled",
		explanation: "Turning off certificate checks allows man-in-the-middle attacks.",
		suggestion:  "Keep verification on; add the internal CA to the trust store instead.",
		re:          regexp.MustCompile(`rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*["']?0|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)`)},
	{id: "jwt-no-verify", severity: "high", category: "auth", title: "JWT signature not verified",
		explanation: "Tokens are decoded without verifying the signature, or the 'none' algorithm is allowed.",
		suggestion:  "Verify tokens with the expected algorithm and key.",
		re:          regexp.MustCompile(`(?i)algorithms\s*[:=]\s*\[\s*["']none["']|verify_signature["']?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False|jwt\.decode\s*\(\s*\w+\s*\)`)},
	{id: "xss-raw-html", severity: "medium", category: "xss", title: "Raw HTML rendered",
		explanation: "Injecting HTML that may contain user input allows cross-site scripting.",
		suggestion:  "Render text instead, or sanitize with a vetted library (e.g. DOMPurify) first.",
		re:          regexp.MustCompile(`dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|v-html\s*=|\|\s*safe\b|mark_safe\s*\(`)},
	{id: "cors-wildcard", severity: "medium", category: "config", title: "CORS allows every origin",
		explanation: "Any website can call this API from a user's browser.",
		suggestion:  "Allow only the origins that need access.",
		re:          regexp.MustCompile(`(?i)(Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*|origin\s*:\s*["']\*["']|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|AllowAllOrigins\s*:\s*true)`)},
	{id: "weak-hash", severity: "medium", category: "crypto", title: "Weak hash algorithm",
		explanation: "MD5 and SHA-1 are broken for security uses such as passwords and signatures.",
		suggestion:  "Use SHA-256 for integrity, and bcrypt/scrypt/argon2 for passwords.",
		re:          regexp.MustCompile(`(?i)createHash\s*\(\s*["'](md5|sha1)["']|hashlib\.(md5|sha1)\s*\(|\bmd5\.New\(|\bsha1\.New\(|MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1)["']`)},
	{id: "debug-enabled", severity: "medium", category: "config", title: "Debug mode enabled",
		explanation: "Debug mode exposes stack traces and internals in production.", suggestion: "Read the flag from the environment and keep it off in production.",
		re: regexp.MustCompile(`^\s*DEBUG\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True`)},
	{id: "insecure-random", severity: "low", category: "crypto", title: "Non-cryptographic random used for a secret",
		explanation: "Math.random / random.random are predictable; tokens or passwords built from them can be guessed.",
		suggestion:  "Use crypto.randomBytes / secrets / crypto/rand.",
		re:          regexp.MustCompile(`(?i)(token|secret|password|nonce|salt|otp)\w*\s*[:=].*(Math\.random\(|random\.random\(|rand\.Intn\()`)},
	// GitHub Actions workflows.
	{id: "actions-script-injection", severity: "high", category: "ci", title: "Untrusted input in a workflow script",
		explanation: "PR titles, bodies or branch names expanded inside run: can execute attacker commands in CI.",
		suggestion:  "Pass the value through an env: variable and quote it in the script.",
		re:          regexp.MustCompile(`\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit)\.(title|body|head\.ref|label|message)|head_ref)[^}]*\}\}`),
		files:       isWorkflow},
	{id: "actions-pull-request-target", severity: "high", category: "ci", title: "pull_request_target workflow",
		explanation: "pull_request_target runs with secrets and write access; checking out the PR head there runs untrusted code.",
		suggestion:  "Use pull_request, or never check out or run the PR's code in this workflow.",
		re:          regexp.MustCompile(`\bpull_request_target\b`), files: isWorkflow},
	{id: "actions-write-all", severity: "medium", category: "ci", title: "Workflow token has write-all permissions",
		explanation: "Every job gets a token that can push code and change the repository.",
		suggestion:  "Grant the minimum, e.g. permissions: { contents: read }.",
		re:          regexp.MustCompile(`permissions\s*:\s*write-all`), files: isWorkflow},
	{id: "curl-pipe-shell", severity: "low", category: "supply-chain", title: "Script piped from the internet into a shell",
		explanation: "curl | sh runs whatever the server returns, unpinned and unverified.",
		suggestion:  "Download a pinned version, verify its checksum, then run it.",
		re:          regexp.MustCompile(`(curl|wget)\s[^|]*\|\s*(sudo\s+)?(ba)?sh\b`),
		files: func(p string) bool {
			return isWorkflow(p) || strings.Contains(path.Base(p), "Dockerfile") || ext(p) == ".sh"
		}},
}

const maxFindingsPerRule = 5

// Review runs the rules over the added lines of every file.
func Review(files []File) (findings []render.ReviewFinding, reviewed int) {
	perRule := map[string]int{}
	for _, f := range files {
		if f.Status == "removed" || f.Patch == "" {
			continue
		}
		reviewed++
		lines := AddedLines(f.Patch)
		for _, r := range rules {
			applies := r.files
			if applies == nil {
				applies = isSource
			}
			if !applies(f.Path) {
				continue
			}
			for _, l := range lines {
				if perRule[r.id] >= maxFindingsPerRule {
					break
				}
				if !r.re.MatchString(l.Text) || (r.skip != nil && r.skip.MatchString(l.Text)) || (r.category != "secrets" && isCommentOnly(l.Text)) {
					continue
				}
				perRule[r.id]++
				expl := r.explanation
				if r.category == "secrets" {
					expl += " Found: " + Mask(r.re.FindString(l.Text)) + "."
				}
				findings = append(findings, render.ReviewFinding{Source: "rules", File: f.Path, Line: l.Line, Severity: r.severity,
					Category: r.category, Title: r.title, Explanation: expl, Suggestion: r.suggestion})
			}
		}
	}
	return findings, reviewed
}

// Mask hides a secret, keeping a short prefix so it can be found and rotated:
// "AKIA…(20 chars)". Values never reach the database or the PR comment.
func Mask(v string) string {
	if v == "" {
		return "a secret value"
	}
	n := 4
	if len(v) < 12 {
		n = 2
	}
	return fmt.Sprintf("`%s…` (%d characters)", v[:n], len(v))
}

func isCommentOnly(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#!") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*")
}

// Labels derives PR labels from the changed paths, the size and the findings.
func Labels(files []File, findings []render.ReviewFinding) []string {
	set := map[string]bool{}
	add, del := 0, 0
	for _, f := range files {
		p := f.Path
		add, del = add+f.Additions, del+f.Deletions
		b := strings.ToLower(path.Base(p))
		switch {
		case isWorkflow(p) || strings.HasPrefix(p, ".gitlab-ci") || b == "jenkinsfile" || strings.HasPrefix(p, ".circleci/") || b == "bitbucket-pipelines.yml":
			set["ci"] = true
		case ext(p) == ".md" || ext(p) == ".mdx" || ext(p) == ".rst" || strings.HasPrefix(p, "docs/"):
			set["docs"] = true
		case isTest(p):
			set["tests"] = true
		case isLockfile(p) || isManifest(b):
			set["dependencies"] = true
		case strings.Contains(b, "dockerfile") || ext(p) == ".tf" || strings.HasPrefix(p, "k8s/") || strings.HasPrefix(p, "helm/") || b == "docker-compose.yml" || b == "compose.yml":
			set["infra"] = true
		case strings.Contains(p, "migration") || ext(p) == ".sql":
			set["database"] = true
		case ext(p) == ".tsx" || ext(p) == ".jsx" || ext(p) == ".vue" || ext(p) == ".svelte" || ext(p) == ".css" || ext(p) == ".scss" || ext(p) == ".html":
			set["frontend"] = true
		case isSource(p):
			set["backend"] = true
		case ext(p) == ".yml" || ext(p) == ".yaml" || ext(p) == ".toml" || ext(p) == ".ini" || strings.HasPrefix(b, ".env") || ext(p) == ".json":
			set["config"] = true
		}
	}
	for _, f := range findings {
		set["security"] = true
		if f.Category == "secrets" {
			set["secrets"] = true
		}
	}
	switch n := add + del; {
	case n < 10:
		set["size/XS"] = true
	case n < 100:
		set["size/S"] = true
	case n < 500:
		set["size/M"] = true
	case n < 1000:
		set["size/L"] = true
	default:
		set["size/XL"] = true
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	slices.Sort(out)
	return out
}

func isTest(p string) bool {
	l := strings.ToLower(p)
	b := path.Base(l)
	return strings.Contains(l, "/test/") || strings.Contains(l, "/tests/") || strings.HasPrefix(l, "test/") || strings.HasPrefix(l, "tests/") ||
		strings.Contains(l, "__tests__/") || strings.HasSuffix(b, "_test.go") || strings.Contains(b, ".test.") || strings.Contains(b, ".spec.") ||
		strings.HasPrefix(b, "test_") || strings.HasSuffix(strings.TrimSuffix(b, path.Ext(b)), "_test")
}

var lockfiles = map[string]bool{"package-lock.json": true, "npm-shrinkwrap.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"bun.lock": true, "bun.lockb": true, "poetry.lock": true, "uv.lock": true, "pipfile.lock": true, "pdm.lock": true, "go.sum": true,
	"cargo.lock": true, "gemfile.lock": true, "composer.lock": true, "pubspec.lock": true, "mix.lock": true, "packages.lock.json": true}

func isLockfile(p string) bool { return lockfiles[strings.ToLower(path.Base(p))] }

func isManifest(b string) bool {
	switch b {
	case "package.json", "requirements.txt", "pyproject.toml", "go.mod", "cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
		"gemfile", "composer.json", "pipfile", "setup.py", "setup.cfg":
		return true
	}
	return false
}

// Reviewable reports whether a file's diff is worth sending to the AI review:
// source, configuration and workflows; not lockfiles, vendored, generated,
// minified or binary files.
func Reviewable(f File) bool {
	p := strings.ToLower(f.Path)
	if f.Patch == "" || f.Status == "removed" || isLockfile(p) {
		return false
	}
	for _, s := range []string{"vendor/", "node_modules/", "dist/", "build/", "third_party/", ".min.", "generated", "__snapshots__/", ".snap"} {
		if strings.Contains(p, s) {
			return false
		}
	}
	return isSource(p) || isWorkflow(f.Path) || strings.Contains(path.Base(p), "dockerfile") ||
		ext(p) == ".yml" || ext(p) == ".yaml" || ext(p) == ".sh" || ext(p) == ".tf" || ext(p) == ".sql" || ext(p) == ".html"
}
