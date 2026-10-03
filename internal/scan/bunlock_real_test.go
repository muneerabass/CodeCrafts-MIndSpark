package scan

import (
	"os"
	"testing"
)

// TestBunLockReal checks a real bun.lock: BUN_LOCK=path BUN_PKG=package.json go test -run TestBunLockReal
func TestBunLockReal(t *testing.T) {
	lock, pj := os.Getenv("BUN_LOCK"), os.Getenv("BUN_PKG")
	if lock == "" {
		t.Skip("BUN_LOCK not set")
	}
	ms, err := Parse([]Lockfile{{Path: lock, RepoPath: "bun.lock"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(lock)
	pb, _ := os.ReadFile(pj)
	m := ms[0]
	AddLockEdges(m, "bun.lock", b)
	g := BuildGraph(m, ReadDirectDeps(m.Ecosystem, map[string][]byte{"package.json": pb}))
	direct, reach, maxDepth := 0, 0, 0
	for _, p := range m.GetPackages() {
		in, ok := g.Info(p)
		if !ok || in.Depth == 0 {
			continue
		}
		reach++
		if in.Direct {
			direct++
		}
		maxDepth = max(maxDepth, in.Depth)
	}
	t.Logf("source=%s packages=%d reachable=%d direct=%d maxDepth=%d", g.Source(), len(m.GetPackages()), reach, direct, maxDepth)
}
