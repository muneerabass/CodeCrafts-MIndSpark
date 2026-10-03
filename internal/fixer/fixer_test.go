package fixer

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinRequirement(t *testing.T) {
	dir := t.TempDir()
	in := "# deps\nRequests[socks]>=2.0 ; python_version > '3.8'  # http\nflask==2.0.1\nrequests-oauthlib==1.0\n"
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(in), 0o600)
	changed, err := Apply(context.Background(), dir, "PyPI", "app/requirements.txt", "requests", "2.31.0", true)
	if err != nil || len(changed) != 1 {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "requirements.txt"))
	want := "# deps\nRequests[socks]==2.31.0 ; python_version > '3.8'  # http\nflask==2.0.1\nrequests-oauthlib==1.0\n"
	if string(b) != want {
		t.Fatalf("got\n%s", b)
	}
	if _, err := Apply(context.Background(), dir, "PyPI", "requirements.txt", "django", "4.2", true); !errors.Is(err, ErrNoChange) {
		t.Fatalf("missing package: %v", err)
	}
}

func TestUnsupported(t *testing.T) {
	for _, c := range [][2]string{{"npm", "yarn.lock"}, {"PyPI", "poetry.lock"}, {"Cargo", "Cargo.lock"}, {"Maven", "pom.xml"}} {
		if Inputs(c[0], c[1]) != nil {
			t.Errorf("%v should be unsupported", c)
		}
		if _, err := Apply(context.Background(), t.TempDir(), c[0], c[1], "x", "1", true); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%v: %v", c, err)
		}
	}
}

// TestNPM needs npm and the registry; run with DEPGUARD_NET_TESTS=1.
func TestNPM(t *testing.T) {
	if os.Getenv("DEPGUARD_NET_TESTS") == "" {
		t.Skip("set DEPGUARD_NET_TESTS=1")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}`), 0o600)
	if err := run(context.Background(), dir, "npm", "install", "--package-lock-only", "--ignore-scripts"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRET_SHOULD_NOT_LEAK", "x")
	changed, err := Apply(context.Background(), dir, "npm", "package-lock.json", "lodash", "4.17.21", true)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if len(changed) != 2 || !strings.Contains(string(b), "lodash-4.17.21.tgz") {
		t.Fatalf("changed=%v", changed)
	}
}
