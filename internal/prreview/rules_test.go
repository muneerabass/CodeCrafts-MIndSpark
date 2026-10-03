package prreview

import (
	"slices"
	"strings"
	"testing"

	"github.com/depguard/depguard/internal/render"
)

func patch(lines ...string) string {
	return "@@ -1,1 +10," + "9 @@\n context\n+" + strings.Join(lines, "\n+") + "\n"
}

func rulesHit(path string, lines ...string) []string {
	fs, _ := Review([]File{{Path: path, Status: "modified", Patch: patch(lines...)}})
	var out []string
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}

func TestAddedLines(t *testing.T) {
	p := "@@ -3,4 +3,5 @@ func x() {\n a\n-b\n+c\n+d\n e\n\\ No newline at end of file\n@@ -20,2 +21,3 @@\n f\n+g\n"
	got := AddedLines(p)
	want := []AddedLine{{4, "c"}, {5, "d"}, {22, "g"}}
	if !slices.Equal(got, want) {
		t.Fatalf("AddedLines = %v, want %v", got, want)
	}
}

func TestRules(t *testing.T) {
	cases := []struct {
		path  string
		line  string
		title string // "" = must not match anything
	}{
		{"app.js", `const key = "AKIAIOSFODNN7EXAMPLE";`, "AWS access key committed"},
		{"config/.env.production", `GITHUB_TOKEN=ghp_` + strings.Repeat("a", 36), "API token committed"},
		{"deploy/key.pem", `-----BEGIN RSA PRIVATE KEY-----`, "Private key committed"},
		{"settings.py", `PASSWORD = "Sup3rS3cretValue!"`, "Hard-coded password or secret"},
		{"settings.py", `PASSWORD = os.environ["DB_PASSWORD"]`, ""},
		{"settings.py", `password = "changeme-example"`, ""},
		{"api/users.js", `db.query("SELECT * FROM users WHERE id = " + req.query.id)`, "SQL query built from untrusted input"},
		{"api/users.ts", "await db.query(`SELECT * FROM users WHERE id = ${id}`)", "SQL query built from untrusted input"},
		{"api/users.py", `cursor.execute(f"SELECT * FROM users WHERE id = {uid}")`, "SQL query built from untrusted input"},
		{"api/users.js", `db.query("SELECT * FROM users WHERE id = $1", [id])`, ""},
		{"run.js", "exec(`git clone ${url}`)", "Shell command built from input"},
		{"run.py", `subprocess.run(cmd, shell=True)`, "Shell command built from input"},
		{"run.py", `subprocess.run(["git", "clone", url])`, ""},
		{"calc.js", `const r = eval(userInput)`, "Dynamic code execution"},
		{"calc.js", `const m = /a+/.exec(text)`, ""},
		{"load.py", `data = pickle.loads(body)`, "Unsafe deserialization"},
		{"load.py", `cfg = yaml.load(f)`, "Unsafe deserialization"},
		{"load.py", `cfg = yaml.load(f, Loader=yaml.SafeLoader)`, ""},
		{"client.js", `https.request({ rejectUnauthorized: false })`, "TLS certificate verification disabled"},
		{"client.py", `requests.get(url, verify=False)`, "TLS certificate verification disabled"},
		{"client.go", `tls.Config{InsecureSkipVerify: true}`, "TLS certificate verification disabled"},
		{"auth.py", `jwt.decode(token, options={"verify_signature": False})`, "JWT signature not verified"},
		{"Page.tsx", `<div dangerouslySetInnerHTML={{ __html: html }} />`, "Raw HTML rendered"},
		{"server.js", `res.setHeader("Access-Control-Allow-Origin", "*")`, "CORS allows every origin"},
		{"hash.js", `crypto.createHash('md5').update(pw)`, "Weak hash algorithm"},
		{"settings.py", `DEBUG = True`, "Debug mode enabled"},
		{"token.js", `const resetToken = Math.random().toString(36)`, "Non-cryptographic random used for a secret"},
		{".github/workflows/ci.yml", `      run: echo "${{ github.event.pull_request.title }}"`, "Untrusted input in a workflow script"},
		{".github/workflows/ci.yml", `on: pull_request_target`, "pull_request_target workflow"},
		{".github/workflows/ci.yml", `permissions: write-all`, "Workflow token has write-all permissions"},
		{"Dockerfile", `RUN curl -fsSL https://x.sh | sh`, "Script piped from the internet into a shell"},
		{"api/users.js", `// db.query("SELECT * FROM users WHERE id = " + id)`, ""},
		{"README.md", `db.query("SELECT * FROM users WHERE id = " + id)`, ""}, // docs are not source
	}
	for _, c := range cases {
		got := rulesHit(c.path, c.line)
		if c.title == "" {
			if len(got) != 0 {
				t.Errorf("%s %q: unexpected %v", c.path, c.line, got)
			}
			continue
		}
		if !slices.Contains(got, c.title) {
			t.Errorf("%s %q: got %v, want %q", c.path, c.line, got, c.title)
		}
	}
}

func TestFindingLineNumbers(t *testing.T) {
	fs, n := Review([]File{{Path: "a.py", Status: "added", Patch: "@@ -0,0 +1,3 @@\n+import os\n+x = 1\n+requests.get(u, verify=False)\n"},
		{Path: "gone.py", Status: "removed", Patch: "@@ -1 +0,0 @@\n-requests.get(u, verify=False)\n"}})
	if n != 1 || len(fs) != 1 || fs[0].Line != 3 || fs[0].File != "a.py" || fs[0].Source != "rules" {
		t.Fatalf("got %d reviewed, %+v", n, fs)
	}
}

func TestLabels(t *testing.T) {
	files := []File{
		{Path: ".github/workflows/ci.yml", Additions: 3}, {Path: "docs/guide.md", Additions: 20}, {Path: "web/app/page.tsx", Additions: 30},
		{Path: "internal/api/server.go", Additions: 40}, {Path: "internal/api/server_test.go", Additions: 10}, {Path: "package-lock.json", Additions: 100},
		{Path: "migrations/0001_init.sql", Additions: 5}, {Path: "Dockerfile", Additions: 2},
	}
	got := Labels(files, nil)
	want := []string{"backend", "ci", "database", "dependencies", "docs", "frontend", "infra", "size/M", "tests"}
	if !slices.Equal(got, want) {
		t.Errorf("labels %v, want %v", got, want)
	}
	if l := Labels([]File{{Path: "a.go", Additions: 1}}, renderFindings{{Category: "secrets"}}.conv()); !slices.Contains(l, "security") || !slices.Contains(l, "secrets") || !slices.Contains(l, "size/XS") {
		t.Errorf("finding labels %v", l)
	}
}

func TestReviewable(t *testing.T) {
	for p, want := range map[string]bool{"src/app.ts": true, "package-lock.json": false, "vendor/x/y.go": false, "dist/app.min.js": false,
		".github/workflows/ci.yml": true, "Dockerfile": true, "logo.png": false, "db/schema.sql": true} {
		if got := Reviewable(File{Path: p, Patch: "@@ -1 +1 @@\n+x"}); got != want {
			t.Errorf("Reviewable(%s)=%v want %v", p, got, want)
		}
	}
}

type renderFinding struct{ Category string }
type renderFindings []renderFinding

func (fs renderFindings) conv() []render.ReviewFinding {
	var out []render.ReviewFinding
	for _, f := range fs {
		out = append(out, render.ReviewFinding{Category: f.Category})
	}
	return out
}
