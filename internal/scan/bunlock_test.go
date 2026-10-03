package scan

import (
	"os"

	"github.com/safedep/vet/pkg/models"
	"path/filepath"
	"testing"
)

const bunLock = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": { "express": "^4.21.2", },
      "devDependencies": { "typescript": "^5", },
    },
  },
  "packages": {
    "express": ["express@4.21.2", "", { "dependencies": { "debug": "2.6.9", "send": "0.19.0", }, }, "sha512-x"],
    "debug": ["debug@2.6.9", "", { "dependencies": { "ms": "2.0.0" } }, "sha512-x"],
    "ms": ["ms@2.0.0", "", {}, "sha512-x"],
    "send": ["send@0.19.0", "", { "dependencies": { "debug": "2.6.9", "ms": "2.1.3" } }, "sha512-x"],
    "send/ms": ["ms@2.1.3", "", {}, "sha512-x"],
    "typescript": ["typescript@5.6.3", "", { "bin": { "tsc": "bin/tsc" } }, "sha512-x"],
  }
}
`

func TestBunLockGraph(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bun.lock")
	if err := os.WriteFile(p, []byte(bunLock), 0o600); err != nil {
		t.Fatal(err)
	}
	ms, err := Parse([]Lockfile{{Path: p, RepoPath: "bun.lock"}})
	if err != nil || len(ms) != 1 {
		t.Fatalf("parse: %v %d", err, len(ms))
	}
	m := ms[0]
	AddLockEdges(m, "bun.lock", []byte(bunLock))
	g := BuildGraph(m, ReadDirectDeps(m.Ecosystem, map[string][]byte{"package.json": []byte(`{"dependencies":{"express":"^4.21.2"},"devDependencies":{"typescript":"^5"}}`)}))
	if g.Source() != GraphLockfile {
		t.Fatalf("source %s", g.Source())
	}
	want := map[string]struct {
		direct bool
		depth  int
		via    string
	}{
		"express@4.21.2":   {true, 1, "express@4.21.2"},
		"typescript@5.6.3": {true, 1, "typescript@5.6.3"},
		"debug@2.6.9":      {false, 2, "express@4.21.2 debug@2.6.9"},
		"ms@2.0.0":         {false, 3, "express@4.21.2 debug@2.6.9 ms@2.0.0"},
		"ms@2.1.3":         {false, 3, "express@4.21.2 send@0.19.0 ms@2.1.3"}, // nested send/ms, not the hoisted ms
	}
	for _, p := range m.GetPackages() {
		in, ok := g.Info(p)
		w, exp := want[p.GetName()+"@"+p.GetVersion()]
		if !exp {
			continue
		}
		var via string
		var first []*models.Package
		if len(in.Paths) > 0 {
			first = in.Paths[0]
		}
		for i, x := range first {
			if i > 0 {
				via += " "
			}
			via += x.GetName() + "@" + x.GetVersion()
		}
		if !ok || in.Direct != w.direct || in.Depth != w.depth || via != w.via {
			t.Errorf("%s@%s: direct=%v depth=%d via=%q; want %+v", p.GetName(), p.GetVersion(), in.Direct, in.Depth, via, w)
		}
	}
	for _, p := range m.GetPackages() {
		if p.GetName() == "typescript" {
			if in, _ := g.Info(p); !in.Dev {
				t.Error("typescript should be dev-only")
			}
		}
	}
}

func TestParentKeyAndTrailingCommas(t *testing.T) {
	for k, want := range map[string]string{"a": "", "a/b": "a", "@s/a/b": "@s/a", "a/@s/b": "a", "@s/a/@t/b": "@s/a"} {
		if got := parentKey(k); got != want {
			t.Errorf("parentKey(%q)=%q want %q", k, got, want)
		}
	}
	if got := string(stripTrailingCommas([]byte(`{"a": [1, 2,], "b": "x,}",}`))); got != `{"a": [1, 2], "b": "x,}"}` {
		t.Errorf("strip: %s", got)
	}
}
