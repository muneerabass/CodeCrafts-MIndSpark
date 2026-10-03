package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestResolveClientIgnoresRepoURL(t *testing.T) {
	t.Setenv("DEPGUARD_CONFIG_DIR", t.TempDir())
	t.Setenv("DEPGUARD_API_URL", "")
	t.Setenv("DEPGUARD_API_KEY", "")
	if err := saveCredentials(credentials{APIURL: "https://good.example", APIKey: "dg_secret"}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	prev := out
	out = &buf
	defer func() { out = prev }()

	c, err := resolveClient("", "", &projectConfig{APIURL: "https://evil.example"})
	if err != nil || c.base != "https://good.example" {
		t.Fatalf("base = %v, %v; want the saved URL", c, err)
	}
	if !strings.Contains(buf.String(), "ignoring api_url") {
		t.Errorf("no warning for an untrusted api_url: %q", buf.String())
	}

	buf.Reset()
	if c, _ := resolveClient("", "", &projectConfig{APIURL: "https://good.example/"}); c.base != "https://good.example" || buf.Len() != 0 {
		t.Errorf("matching api_url: base %s, output %q", c.base, buf.String())
	}

	t.Setenv("DEPGUARD_API_URL", "https://env.example")
	buf.Reset()
	if c, _ := resolveClient("", "", &projectConfig{APIURL: "https://env.example"}); c.base != "https://env.example" || buf.Len() != 0 {
		t.Errorf("env api_url: base %s, output %q", c.base, buf.String())
	}
}

func TestFindProjectStopsAtRepoRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	write(t, root, ".depguard.yml", "project: outside\n")
	write(t, root, "repo/.git/HEAD", "ref: refs/heads/main\n")
	write(t, root, "repo/sub/x", "")
	write(t, root, "home/proj/x", "")

	if pc, err := findProject(filepath.Join(root, "repo", "sub")); err != nil || pc != nil {
		t.Errorf("found %+v above the git root", pc)
	}
	if pc, err := findProject(filepath.Join(root, "home", "proj")); err != nil || pc != nil {
		t.Errorf("found %+v above $HOME", pc)
	}
	write(t, root, "repo/.depguard.yml", "project: inside\n")
	if pc, err := findProject(filepath.Join(root, "repo", "sub")); err != nil || pc == nil || pc.Project != "inside" {
		t.Errorf("findProject = %+v, %v; want the repo's file", pc, err)
	}
}

func TestCacheKey(t *testing.T) {
	rules := []rule{{Name: "left-pad", Deny: true}}
	base := cacheKey("https://a", "dg_1", rules, "lock")
	for name, k := range map[string]string{
		"url":   cacheKey("https://b", "dg_1", rules, "lock"),
		"key":   cacheKey("https://a", "dg_2", rules, "lock"),
		"rules": cacheKey("https://a", "dg_1", []rule{{Name: "left-pad"}}, "lock"),
		"lock":  cacheKey("https://a", "dg_1", rules, "lock2"),
	} {
		if k == base {
			t.Errorf("cache key ignores the %s", name)
		}
	}
	if base != cacheKey("https://a/", "dg_1", rules, "lock") {
		t.Error("cache key is not stable")
	}
	e := cacheEntry{At: time.Now(), PolicyVersion: "v1"}
	if !e.valid("v1") || e.valid("v2") || e.valid("") {
		t.Error("policy_version must match")
	}
	if (cacheEntry{At: time.Now().Add(-13 * time.Hour), PolicyVersion: "v1"}).valid("v1") {
		t.Error("expired entry is valid")
	}
}

func TestRewriteReplaces(t *testing.T) {
	root := filepath.FromSlash("/src/app")
	in := "module app\n\nreplace example.com/a => ../a\n\nreplace (\n\texample.com/b v1.0.0 => ./b // local\n\texample.com/c => example.com/d v1.2.3\n)\n"
	want := "module app\n\nreplace example.com/a => " + filepath.Join(root, "../a") + "\n\nreplace (\n\texample.com/b v1.0.0 => " + filepath.Join(root, "b") + " // local\n\texample.com/c => example.com/d v1.2.3\n)\n"
	if got := string(rewriteReplaces([]byte(in), root)); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestResolveGoLocalReplace(t *testing.T) {
	bin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not installed")
	}
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOFLAGS", "")
	root := t.TempDir()
	write(t, root, "lib/go.mod", "module example.com/lib\n\ngo 1.21\n")
	write(t, root, "app/go.mod", "module app\n\ngo 1.21\n\nrequire example.com/lib v0.0.0\n\nreplace example.com/lib => ../lib\n")
	before, _ := os.ReadFile(filepath.Join(root, "app/go.mod"))
	if _, err := resolveGo(invocation{tool: "go", sub: "mod"}, filepath.Join(root, "app"), bin); err != nil {
		t.Fatalf("resolveGo: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(root, "app/go.mod")); !bytes.Equal(before, after) {
		t.Error("resolution changed the real go.mod")
	}
}

func TestYarnLockVersions(t *testing.T) {
	classic := `# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/x"

lodash@^4.17.15:
  version "4.17.21"
`
	berry := `__metadata:
  version: 6

"left-pad@npm:^1.3.0":
  version: 1.3.0
  resolution: "left-pad@npm:1.3.0"
`
	got := yarnLockVersions([]byte(classic + berry))
	for _, k := range []string{"@babel/code-frame@7.12.13", "lodash@4.17.21", "left-pad@1.3.0"} {
		if !got[k] {
			t.Errorf("missing %s in %v", k, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("unexpected entries: %v", got)
	}
}

func TestJSWorkspace(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"workspaces": ["packages/*", "../escape"]}`)
	write(t, root, "packages/a/package.json", `{}`)
	write(t, root, "packages/b/package.json", `{}`)
	write(t, filepath.Dir(root), "escape/package.json", `{}`)
	ws, members := jsWorkspace(filepath.Join(root, "packages", "a"))
	if ws != root || len(members) != 2 {
		t.Errorf("jsWorkspace = %s %v", ws, members)
	}
}

func TestSafeArgs(t *testing.T) {
	abs, _ := filepath.Abs("x")
	got := safeArgs([]string{"add", "serde", "--manifest-path", abs, "--prefix=" + abs, "-C", "rel"})
	if strings.Join(got, " ") != "add serde -C rel" {
		t.Errorf("safeArgs = %v", got)
	}
}

func TestRealToolSkipsShims(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	root := t.TempDir()
	shims, link, copied, real := filepath.Join(root, "shims"), filepath.Join(root, "link"), filepath.Join(root, "copy"), filepath.Join(root, "real")
	write(t, root, "shims/faketool", "#!/bin/sh\nexit 3\n") // no marker: skipped as the shim dir
	write(t, root, "copy/faketool", "#!/bin/sh\n# depguard install guard: checks installs\nexit 3\n")
	write(t, root, "real/faketool", "#!/bin/sh\nexit 0\n")
	for _, d := range []string{shims, copied, real} {
		if err := os.Chmod(filepath.Join(d, "faketool"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(shims, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEPGUARD_SHIM_DIR", shims)
	t.Setenv("PATH", strings.Join([]string{link, copied, real}, string(os.PathListSeparator)))
	if got, err := realTool("faketool"); err != nil || got != filepath.Join(real, "faketool") {
		t.Errorf("realTool = %q, %v; want %s", got, err, filepath.Join(real, "faketool"))
	}
}
