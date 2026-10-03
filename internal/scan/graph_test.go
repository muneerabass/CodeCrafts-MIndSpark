package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/safedep/vet/pkg/models"
)

// testLock is an npm v3 lockfile: express (prod) and jest (dev) are direct;
// a diamond express→{a,b}→c; side-channel reachable from both roots via qs;
// d has four shortest paths (express→e1..e4→d).
func testLock(t *testing.T) (*models.PackageManifest, []byte) {
	t.Helper()
	pkg := func(ver string, dev bool, deps ...string) map[string]any {
		m := map[string]any{"version": ver}
		if dev {
			m["dev"] = true
		}
		if len(deps) > 0 {
			d := map[string]string{}
			for _, x := range deps {
				d[x] = "*"
			}
			m["dependencies"] = d
		}
		return m
	}
	packages := map[string]any{
		"": map[string]any{"name": "app", "version": "1.0.0",
			"dependencies": map[string]string{"express": "^4.0.0"}, "devDependencies": map[string]string{"jest": "^29.0.0"}},
		"node_modules/express":      pkg("4.0.0", false, "body-parser", "qs", "a", "b", "e1", "e2", "e3", "e4"),
		"node_modules/body-parser":  pkg("1.0.0", false, "qs"),
		"node_modules/qs":           pkg("6.0.0", false, "side-channel"),
		"node_modules/side-channel": pkg("1.0.0", false),
		"node_modules/a":            pkg("1.0.0", false, "c"),
		"node_modules/b":            pkg("1.0.0", false, "c"),
		"node_modules/c":            pkg("1.0.0", false),
		"node_modules/e1":           pkg("1.0.0", false, "d"),
		"node_modules/e2":           pkg("1.0.0", false, "d"),
		"node_modules/e3":           pkg("1.0.0", false, "d"),
		"node_modules/e4":           pkg("1.0.0", false, "d"),
		"node_modules/d":            pkg("1.0.0", false),
		"node_modules/jest":         pkg("29.0.0", true, "jest-core", "qs"),
		"node_modules/jest-core":    pkg("29.0.0", true),
		"node_modules/fsevents":     map[string]any{"version": "2.3.3", "optional": true},
	}
	packages["node_modules/express"].(map[string]any)["optionalDependencies"] = map[string]string{"fsevents": "^2"}
	data, _ := json.Marshal(map[string]any{"name": "app", "lockfileVersion": 3, "requires": true, "packages": packages})
	p := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ms, err := Parse([]Lockfile{{Path: p, RepoPath: "package-lock.json"}})
	if err != nil || len(ms) != 1 {
		t.Fatalf("parse: %v %d", err, len(ms))
	}
	return ms[0], data
}

func find(t *testing.T, m *models.PackageManifest, name string) *models.Package {
	t.Helper()
	for _, p := range m.GetPackages() {
		if p.GetName() == name {
			return p
		}
	}
	t.Fatalf("package %s not found", name)
	return nil
}

func chains(in GraphInfo) []string {
	var out []string
	for _, p := range in.Paths {
		out = append(out, strings.Join(Chain(p), " > "))
	}
	return out
}

func TestBuildGraphLockfile(t *testing.T) {
	m, data := testLock(t)
	if in, _ := BuildGraph(m, nil).Info(find(t, m, "fsevents")); !in.Direct {
		t.Fatalf("vet drops optional edges; fsevents should look direct: %+v", in)
	}
	AddNpmLockEdges(m, data)
	g := BuildGraph(m, ReadDirectDeps(models.EcosystemNpm, map[string][]byte{"package-lock.json": data}))
	if g.Source() != GraphLockfile {
		t.Fatalf("source %s", g.Source())
	}
	info := func(name string) GraphInfo {
		in, ok := g.Info(find(t, m, name))
		if !ok {
			t.Fatalf("no info for %s", name)
		}
		return in
	}
	cases := []struct {
		name   string
		direct bool
		depth  int
		dev    bool
		paths  []string
	}{
		{"express", true, 1, false, []string{"express@4.0.0"}},
		{"jest", true, 1, true, []string{"jest@29.0.0"}},
		{"jest-core", false, 2, true, []string{"jest@29.0.0 > jest-core@29.0.0"}},
		{"qs", false, 2, false, []string{"express@4.0.0 > qs@6.0.0", "jest@29.0.0 > qs@6.0.0"}},
		{"side-channel", false, 3, false, []string{"express@4.0.0 > qs@6.0.0 > side-channel@1.0.0", "jest@29.0.0 > qs@6.0.0 > side-channel@1.0.0"}},
		{"c", false, 3, false, []string{"express@4.0.0 > a@1.0.0 > c@1.0.0", "express@4.0.0 > b@1.0.0 > c@1.0.0"}},
		{"fsevents", false, 2, false, []string{"express@4.0.0 > fsevents@2.3.3"}},
		{"d", false, 3, false, []string{"express@4.0.0 > e1@1.0.0 > d@1.0.0", "express@4.0.0 > e2@1.0.0 > d@1.0.0", "express@4.0.0 > e3@1.0.0 > d@1.0.0"}},
	}
	for _, c := range cases {
		in := info(c.name)
		if in.Direct != c.direct || in.Depth != c.depth || in.Dev != c.dev || !slices.Equal(chains(in), c.paths) {
			t.Errorf("%s: direct=%v depth=%d dev=%v paths=%q", c.name, in.Direct, in.Depth, in.Dev, chains(in))
		}
	}
	var appEdges, edges int
	for _, e := range g.Edges() {
		if e[0] == nil {
			appEdges++
		} else {
			edges++
		}
	}
	if appEdges != 2 || edges != 19 {
		t.Fatalf("edges app=%d deps=%d", appEdges, edges)
	}
	// Without manifest info, jest is still a root (no dependents) but not dev.
	if in, _ := BuildGraph(m, nil).Info(find(t, m, "jest")); !in.Direct || in.Dev {
		t.Fatalf("jest without manifest: %+v", in)
	}
}

func TestBuildGraphNoGraph(t *testing.T) {
	m := models.NewPackageManifestFromLocal("go.mod", models.EcosystemGo)
	for _, n := range []string{"github.com/a/x", "github.com/b/y"} {
		m.AddPackage(&models.Package{PackageDetails: models.NewPackageDetail(models.EcosystemGo, n, "v1.0.0")})
	}
	x, y := m.GetPackages()[0], m.GetPackages()[1]
	if _, ok := BuildGraph(m, nil).Info(x); ok {
		t.Fatal("no direct set: info must be unknown")
	}
	g := BuildGraph(m, []DirectDep{{Name: "github.com/a/x", Version: "v1.0.0"}})
	ix, _ := g.Info(x)
	iy, ok := g.Info(y)
	if g.Source() != GraphNone || !ix.Direct || ix.Depth != 1 || len(ix.Paths) != 1 || !ok || iy.Direct || iy.Depth != 0 {
		t.Fatalf("source=%s x=%+v y=%+v", g.Source(), ix, iy)
	}
}

func TestBuildGraphDepsDev(t *testing.T) {
	m := models.NewPackageManifestFromLocal("Cargo.lock", models.EcosystemCargo)
	for _, nv := range [][2]string{{"r", "1.0.0"}, {"s", "2.0.0"}, {"t", "3.0.0"}, {"lonely", "1.0.0"}} {
		m.AddPackage(&models.Package{PackageDetails: models.NewPackageDetail(models.EcosystemCargo, nv[0], nv[1])})
	}
	fetch := func(name, version string) ([]GraphNode, [][2]int) {
		if name != "r" || version != "1.0.0" {
			return nil, nil
		}
		return []GraphNode{{"r", "1.0.0", "SELF"}, {"S", "2.0.0", "DIRECT"}, {"t", "3.1.0", "INDIRECT"}, {"absent", "1", "INDIRECT"}},
			[][2]int{{0, 1}, {1, 2}, {0, 3}, {3, 2}}
	}
	g := BuildGraphWith(m, []DirectDep{{Name: "r", Version: "^1"}}, fetch)
	is, _ := g.Info(find(t, m, "s"))
	it, _ := g.Info(find(t, m, "t"))
	il, _ := g.Info(find(t, m, "lonely"))
	if g.Source() != GraphDepsDev || is.Depth != 2 || is.Approximate || it.Depth != 3 || !it.Approximate ||
		!slices.Equal(chains(it), []string{"r@1.0.0 > s@2.0.0 > t@3.0.0"}) || il.Direct || il.Depth != 0 {
		t.Fatalf("source=%s s=%+v t=%+v %q lonely=%+v", g.Source(), is, it, chains(it), il)
	}
	// deps.dev has nothing → direct set only.
	if g := BuildGraphWith(m, []DirectDep{{Name: "s"}}, fetch); g.Source() != GraphNone {
		t.Fatalf("fallback source %s", g.Source())
	}
}

func TestBuildGraphRealLock(t *testing.T) {
	const dir = "/home/manas/Documents/the_interview_pict"
	if _, err := os.Stat(dir + "/package-lock.json"); err != nil {
		t.Skip("sample lockfile not present")
	}
	ms, err := Parse([]Lockfile{{Path: dir + "/package-lock.json", RepoPath: "package-lock.json"}})
	if err != nil {
		t.Fatal(err)
	}
	pj, _ := os.ReadFile(dir + "/package.json")
	lock, _ := os.ReadFile(dir + "/package-lock.json")
	AddNpmLockEdges(ms[0], lock)
	deps := ReadDirectDeps(models.EcosystemNpm, map[string][]byte{"package.json": pj})
	g := BuildGraph(ms[0], deps)
	direct := 0
	seen := map[string]bool{}
	for _, p := range ms[0].GetPackages() {
		in, ok := g.Info(p)
		if !ok || len(in.Paths) == 0 || in.Depth != len(in.Paths[0]) || in.Paths[0][len(in.Paths[0])-1] != p {
			t.Fatalf("%s@%s: ok=%v %+v", p.GetName(), p.GetVersion(), ok, in)
		}
		if in.Direct && !seen[p.Id()] { // a lockfile may list the same package twice
			seen[p.Id()] = true
			direct++
		}
	}
	if direct > len(deps) {
		t.Errorf("%d direct packages, package.json declares %d", direct, len(deps))
	}
	t.Logf("%d packages, %d direct, %d edges", len(ms[0].GetPackages()), direct, len(g.Edges()))
}
