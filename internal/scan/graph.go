package scan

import (
	"encoding/json"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/safedep/vet/pkg/models"
)

// Graph sources.
const (
	GraphLockfile = "lockfile"
	GraphDepsDev  = "depsdev"
	GraphNone     = "none"
)

// maxPaths is how many shortest chains are kept per package.
const maxPaths = 3

// GraphInfo is a package's place in its manifest's dependency graph.
type GraphInfo struct {
	Direct bool
	Depth  int  // 1 = direct; 0 = not reachable from a known direct dependency
	Dev    bool // reachable only through dev/test direct dependencies
	// Paths are up to 3 distinct shortest chains, root (direct dep) first,
	// ending with the package itself.
	Paths [][]*models.Package
	// Approximate: a node of the shortest path was mapped from deps.dev by
	// name only (resolved version differs from the lockfile).
	Approximate bool
}

// GraphNode is a node of a deps.dev resolved dependency graph.
type GraphNode struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Relation string `json:"relation"` // SELF | DIRECT | INDIRECT
}

// DepsDevFunc returns the resolved dependency graph of name@version
// (nodes[0] is the package itself; edges are node index pairs from→to).
// It returns nil when unavailable.
type DepsDevFunc func(name, version string) (nodes []GraphNode, edges [][2]int)

// Graph is the dependency graph of one manifest with per-package context.
type Graph struct {
	source string
	info   map[string]*GraphInfo // by Package.Id()
	edges  [][2]*models.Package
}

// Source is lockfile, depsdev or none.
func (g *Graph) Source() string { return g.source }

// Info returns graph context for p; false when unknown.
func (g *Graph) Info(p *models.Package) (GraphInfo, bool) {
	i, ok := g.info[p.Id()]
	if !ok {
		return GraphInfo{}, false
	}
	return *i, true
}

// Edges returns parent→child edges; a nil parent is the application.
func (g *Graph) Edges() [][2]*models.Package { return g.edges }

// BuildGraph builds the graph from the lockfile's dependency graph (vet fills
// it for package-lock.json v2+, uv.lock and CycloneDX). Without one, only the
// direct set from manifests is known.
func BuildGraph(m *models.PackageManifest, direct []DirectDep) *Graph {
	return BuildGraphWith(m, direct, nil)
}

// BuildGraphWith is BuildGraph with a deps.dev fallback: when the lockfile
// has no graph, each direct dependency's resolved subtree from fetch is mapped
// onto lockfile packages by normalized name (exact version preferred, else
// any version, marked approximate).
func BuildGraphWith(m *models.PackageManifest, direct []DirectDep, fetch DepsDevFunc) *Graph {
	g := &Graph{source: GraphNone, info: map[string]*GraphInfo{}}
	pkgs := m.GetPackages()
	byID := map[string]*models.Package{}
	byName := map[string][]*models.Package{}
	for _, p := range pkgs {
		if _, ok := byID[p.Id()]; ok {
			continue
		}
		byID[p.Id()] = p
		n := normName(m.Ecosystem, p.GetName())
		byName[n] = append(byName[n], p)
	}
	for _, ps := range byName { // stable choice among versions
		slices.SortFunc(ps, func(a, b *models.Package) int { return strings.Compare(a.GetVersion(), b.GetVersion()) })
	}
	// dev[name] is true only if every manifest entry for name is dev.
	dev := map[string]bool{}
	for _, d := range direct {
		n := normName(m.Ecosystem, d.Name)
		if v, ok := dev[n]; ok {
			dev[n] = v && d.Dev
		} else {
			dev[n] = d.Dev
		}
	}
	isDevRoot := func(p *models.Package) bool { return dev[normName(m.Ecosystem, p.GetName())] }

	if dg := m.DependencyGraph; dg != nil && dg.Present() {
		g.source = GraphLockfile
		var edges [][2]*models.Package
		hasParent := map[string]bool{}
		seen := map[[2]string]bool{}
		nodes := dg.GetNodes()
		for _, n := range nodes {
			for _, c := range n.Children {
				child := byID[c.Id()]
				if child == nil || c.Id() == n.Data.Id() || seen[[2]string{n.Data.Id(), c.Id()}] {
					continue
				}
				seen[[2]string{n.Data.Id(), c.Id()}] = true
				hasParent[c.Id()] = true
				edges = append(edges, [2]*models.Package{byID[n.Data.Id()], child})
			}
		}
		// Roots: marked by the parser, no dependents (npm dev deps are not
		// marked), or the only version of a manifest direct dependency.
		var roots []*models.Package
		for _, n := range nodes {
			p := byID[n.Data.Id()]
			_, isDirect := dev[normName(m.Ecosystem, p.GetName())]
			// ponytail: a direct name with several installed versions relies on
			// the parser's root marking; semver-match the manifest range if needed.
			if n.Root || !hasParent[p.Id()] || (isDirect && len(byName[normName(m.Ecosystem, p.GetName())]) == 1) {
				roots = append(roots, p)
			}
		}
		g.walk(pkgs, roots, edges, isDevRoot, nil)
		return g
	}
	if len(direct) == 0 {
		return g // nothing known
	}

	var roots []*models.Package
	head := func(d DirectDep) *models.Package {
		cands := byName[normName(m.Ecosystem, d.Name)]
		for _, c := range cands {
			if c.GetVersion() == d.Version || strings.TrimPrefix(c.GetVersion(), "v") == strings.TrimPrefix(d.Version, "v") {
				return c
			}
		}
		if len(cands) > 0 {
			return cands[0]
		}
		return nil
	}
	for _, d := range direct {
		if p := head(d); p != nil && !slices.Contains(roots, p) {
			roots = append(roots, p)
		}
	}
	if fetch != nil {
		var edges [][2]*models.Package
		approx := map[string]bool{}
		seen := map[[2]string]bool{}
		got := false
		for _, r := range roots {
			nodes, es := fetch(r.GetName(), r.GetVersion())
			if len(nodes) == 0 {
				continue
			}
			got = true
			mapped := make([]*models.Package, len(nodes))
			for i, n := range nodes {
				if i == 0 || n.Relation == "SELF" {
					mapped[i] = r
					continue
				}
				cands := byName[normName(m.Ecosystem, n.Name)]
				for _, c := range cands {
					if c.GetVersion() == n.Version {
						mapped[i] = c
					}
				}
				if mapped[i] == nil && len(cands) > 0 {
					mapped[i] = cands[0]
					approx[cands[0].Id()] = true
				}
			}
			for _, e := range es {
				if e[0] < 0 || e[1] < 0 || e[0] >= len(mapped) || e[1] >= len(mapped) {
					continue
				}
				a, b := mapped[e[0]], mapped[e[1]]
				if a == nil || b == nil || a == b || seen[[2]string{a.Id(), b.Id()}] {
					continue
				}
				seen[[2]string{a.Id(), b.Id()}] = true
				edges = append(edges, [2]*models.Package{a, b})
			}
		}
		if got {
			g.source = GraphDepsDev
			g.walk(pkgs, roots, edges, isDevRoot, approx)
			return g
		}
	}
	// Direct set only: direct packages are depth 1, the rest transitive.
	g.walk(pkgs, roots, nil, isDevRoot, nil)
	return g
}

// walk runs a multi-source BFS from roots over edges and fills info for
// every package (unreached packages: not direct, depth 0, no paths).
func (g *Graph) walk(pkgs, roots []*models.Package, edges [][2]*models.Package, isDevRoot func(*models.Package) bool, approx map[string]bool) {
	children := map[string][]*models.Package{}
	parents := map[string][]*models.Package{}
	for _, e := range edges {
		children[e[0].Id()] = append(children[e[0].Id()], e[1])
		parents[e[1].Id()] = append(parents[e[1].Id()], e[0])
	}
	for _, ps := range parents { // deterministic path choice
		slices.SortFunc(ps, func(a, b *models.Package) int { return strings.Compare(label(a), label(b)) })
	}
	slices.SortFunc(roots, func(a, b *models.Package) int { return strings.Compare(label(a), label(b)) })
	roots = slices.CompactFunc(roots, func(a, b *models.Package) bool { return a.Id() == b.Id() })

	bfs := func(from []*models.Package) (map[string]int, []*models.Package) {
		dist := map[string]int{}
		var order []*models.Package
		for _, r := range from {
			dist[r.Id()] = 1
			order = append(order, r)
		}
		for i := 0; i < len(order); i++ {
			v := order[i]
			for _, c := range children[v.Id()] {
				if _, ok := dist[c.Id()]; !ok {
					dist[c.Id()] = dist[v.Id()] + 1
					order = append(order, c)
				}
			}
		}
		return dist, order
	}
	dist, order := bfs(roots)
	prod, _ := bfs(slices.DeleteFunc(slices.Clone(roots), isDevRoot))

	// Shortest paths through BFS predecessors (parents one layer up), at
	// most maxPaths per node; layers strictly increase so paths are simple.
	paths := map[string][][]*models.Package{}
	for _, v := range order {
		id := v.Id()
		if dist[id] == 1 {
			paths[id] = [][]*models.Package{{v}}
			continue
		}
		var out [][]*models.Package
		for _, u := range parents[id] {
			if dist[u.Id()] != dist[id]-1 {
				continue
			}
			for _, p := range paths[u.Id()] {
				if len(out) == maxPaths {
					break
				}
				out = append(out, append(slices.Clip(p), v))
			}
		}
		paths[id] = out
	}

	for _, p := range pkgs {
		id := p.Id()
		if _, ok := g.info[id]; ok {
			continue
		}
		d, reached := dist[id]
		_, inProd := prod[id]
		in := &GraphInfo{Direct: d == 1, Depth: d, Dev: reached && !inProd, Paths: paths[id]}
		if len(in.Paths) > 0 && approx != nil {
			for _, n := range in.Paths[0] {
				in.Approximate = in.Approximate || approx[n.Id()]
			}
		}
		g.info[id] = in
	}
	for _, r := range roots {
		g.edges = append(g.edges, [2]*models.Package{nil, r})
	}
	g.edges = append(g.edges, edges...)
}

// AddNpmLockEdges adds the optionalDependencies/peerDependencies edges that
// vet's npm graph omits (platform binaries, peers), resolving each name the
// way node does: nearest node_modules up from the dependent's location.
// Without them those packages look like extra direct dependencies.
func AddNpmLockEdges(m *models.PackageManifest, lock []byte) {
	dg := m.DependencyGraph
	if dg == nil || !dg.Present() || m.Ecosystem != models.EcosystemNpm {
		return
	}
	var lf struct {
		Packages map[string]struct {
			Name                 string            `json:"name"`
			Version              string            `json:"version"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		} `json:"packages"`
	}
	if json.Unmarshal(lock, &lf) != nil {
		return
	}
	nodes := map[string]*models.Package{}
	for _, n := range dg.GetNodes() {
		nodes[n.Data.Id()] = n.Data
	}
	at := func(loc string) *models.Package {
		e, ok := lf.Packages[loc]
		if !ok || loc == "" {
			return nil
		}
		name := e.Name
		if i := strings.LastIndex(loc, "node_modules/"); i >= 0 {
			name = loc[i+len("node_modules/"):]
		}
		return nodes[(&models.Package{PackageDetails: models.NewPackageDetail(models.EcosystemNpm, name, e.Version)}).Id()]
	}
	resolve := func(from, name string) *models.Package {
		for cur := from; ; {
			loc := "node_modules/" + name
			if cur != "" {
				loc = cur + "/" + loc
			}
			if p := at(loc); p != nil {
				return p
			}
			if cur == "" {
				return nil
			}
			if i := strings.LastIndex(cur, "/node_modules/"); i >= 0 {
				cur = cur[:i]
			} else {
				cur = ""
			}
		}
	}
	locs := make([]string, 0, len(lf.Packages))
	for loc := range lf.Packages {
		locs = append(locs, loc)
	}
	slices.Sort(locs)
	for _, loc := range locs {
		from := at(loc)
		if from == nil {
			continue
		}
		e := lf.Packages[loc]
		for _, deps := range []map[string]string{e.OptionalDependencies, e.PeerDependencies} {
			for name := range deps {
				if to := resolve(loc, name); to != nil && to != from && !slices.Contains(dg.GetDependencies(from), to) {
					dg.AddDependency(from, to)
				}
			}
		}
	}
}

func label(p *models.Package) string { return p.GetName() + "@" + p.GetVersion() }

// Chain renders a path as "name@version" strings.
func Chain(path []*models.Package) []string {
	out := make([]string, len(path))
	for i, p := range path {
		out[i] = label(p)
	}
	return out
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// normName normalizes a package name for matching across manifests,
// lockfiles and deps.dev (case-insensitive; PEP 503 for PyPI).
func normName(eco, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if eco == models.EcosystemPyPI {
		n = pypiSep.ReplaceAllString(n, "-")
	}
	return n
}

// AddLockEdges adds dependency edges that vet's parser leaves out, from the
// raw lockfile (npm package-lock optional/peer deps, bun.lock).
func AddLockEdges(m *models.PackageManifest, displayPath string, lock []byte) {
	switch path.Base(displayPath) {
	case "package-lock.json", "npm-shrinkwrap.json":
		AddNpmLockEdges(m, lock)
	case "bun.lock":
		AddBunLockEdges(m, lock)
	}
}

// AddBunLockEdges builds the dependency graph of a bun.lock (text format,
// JSON with trailing commas). Package keys are install paths ("send/ms" is the
// ms nested under send); a dependency resolves to the nearest enclosing key,
// like node_modules lookup. Workspace dependencies become roots.
func AddBunLockEdges(m *models.PackageManifest, lock []byte) {
	dg := m.DependencyGraph
	if dg == nil || dg.Present() || m.Ecosystem != models.EcosystemNpm {
		return
	}
	type deps struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	var lf struct {
		Workspaces map[string]deps              `json:"workspaces"`
		Packages   map[string][]json.RawMessage `json:"packages"`
	}
	if json.Unmarshal(stripTrailingCommas(lock), &lf) != nil || len(lf.Packages) == 0 {
		return
	}
	nodes := map[string]*models.Package{}
	for _, n := range dg.GetNodes() {
		nodes[n.Data.Id()] = n.Data
	}
	pkgAt := func(key string) *models.Package {
		e := lf.Packages[key]
		if len(e) == 0 {
			return nil
		}
		var ident string
		if json.Unmarshal(e[0], &ident) != nil {
			return nil
		}
		at := strings.LastIndex(ident, "@")
		if at <= 0 {
			return nil
		}
		return nodes[(&models.Package{PackageDetails: models.NewPackageDetail(models.EcosystemNpm, ident[:at], ident[at+1:])}).Id()]
	}
	depsOf := func(key string) []string {
		e := lf.Packages[key]
		var out []string
		for _, raw := range e[1:] {
			var d deps
			if json.Unmarshal(raw, &d) != nil {
				continue
			}
			for _, mp := range []map[string]string{d.Dependencies, d.OptionalDependencies, d.PeerDependencies} {
				for n := range mp {
					out = append(out, n)
				}
			}
		}
		slices.Sort(out)
		return out
	}
	resolve := func(from, name string) *models.Package {
		for cur := from; ; cur = parentKey(cur) {
			k := name
			if cur != "" {
				k = cur + "/" + name
			}
			if p := pkgAt(k); p != nil {
				return p
			}
			if cur == "" {
				return nil
			}
		}
	}
	keys := make([]string, 0, len(lf.Packages))
	for k := range lf.Packages {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	added := false
	for _, k := range keys {
		from := pkgAt(k)
		if from == nil {
			continue
		}
		for _, d := range depsOf(k) {
			if to := resolve(k, d); to != nil && to != from {
				dg.AddDependency(from, to)
				added = true
			}
		}
	}
	for _, ws := range lf.Workspaces {
		for _, mp := range []map[string]string{ws.Dependencies, ws.DevDependencies, ws.OptionalDependencies, ws.PeerDependencies} {
			for n := range mp {
				if p := resolve("", n); p != nil {
					dg.AddRootNode(p)
					added = true
				}
			}
		}
	}
	if added {
		dg.SetPresent(true)
	}
}

// parentKey drops the last package name from a bun.lock key ("a/@s/b" -> "a").
func parentKey(k string) string {
	parts := strings.Split(k, "/")
	n := len(parts) - 1
	if n >= 1 && strings.HasPrefix(parts[n-1], "@") {
		n-- // scoped name spans two segments
	}
	if n <= 0 {
		return ""
	}
	return strings.Join(parts[:n], "/")
}

// stripTrailingCommas makes JSON-with-trailing-commas (bun.lock) valid JSON.
func stripTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\n' || b[j] == '\r' || b[j] == '\t') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}
