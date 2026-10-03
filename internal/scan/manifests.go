package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/safedep/vet/pkg/models"
)

// DirectDep is a dependency declared in a manifest (package.json, go.mod, …).
// Version is what the manifest says: often a range, sometimes empty.
type DirectDep struct {
	Name, Version string
	Dev           bool // dev/test-only dependency
}

// manifestEcosystem maps manifest base names to the vet ecosystem they declare.
var manifestEcosystem = map[string]string{
	"package.json": models.EcosystemNpm, "package-lock.json": models.EcosystemNpm,
	"go.mod": models.EcosystemGo, "pom.xml": models.EcosystemMaven, "Cargo.toml": models.EcosystemCargo,
	"pyproject.toml": models.EcosystemPyPI, "Gemfile": models.EcosystemRubyGems, "composer.json": models.EcosystemPackagist,
}

// IsDirectManifest reports whether ReadDirectDeps understands the file.
func IsDirectManifest(p string) bool {
	b := path.Base(p)
	return manifestEcosystem[b] != "" || isRequirements(b)
}

func isRequirements(base string) bool {
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}

// ReadDirectDeps returns the direct dependencies of ecosystem declared by
// the manifests in files (path → content; base names decide the format).
// package-lock.json's root entry is used only when package.json is absent.
// Unparseable files are skipped.
func ReadDirectDeps(ecosystem string, files map[string][]byte) []DirectDep {
	paths := make([]string, 0, len(files))
	hasPkgJSON := false
	for p := range files {
		paths = append(paths, p)
		hasPkgJSON = hasPkgJSON || path.Base(p) == "package.json"
	}
	slices.Sort(paths)
	var out []DirectDep
	for _, p := range paths {
		b, data := path.Base(p), files[p]
		eco := manifestEcosystem[b]
		if isRequirements(b) {
			eco = models.EcosystemPyPI
		}
		if eco != ecosystem {
			continue
		}
		switch {
		case b == "package.json":
			out = append(out, readPackageJSON(data)...)
		case b == "package-lock.json" && !hasPkgJSON:
			var lf struct {
				Packages map[string]json.RawMessage `json:"packages"`
			}
			if json.Unmarshal(data, &lf) == nil && lf.Packages[""] != nil {
				out = append(out, readPackageJSON(lf.Packages[""])...)
			}
		case b == "go.mod":
			out = append(out, readGoMod(data)...)
		case b == "pom.xml":
			out = append(out, readPom(data)...)
		case b == "Cargo.toml":
			out = append(out, readCargo(data)...)
		case b == "pyproject.toml":
			out = append(out, readPyproject(data)...)
		case isRequirements(b):
			out = append(out, readRequirements(data)...)
		case b == "Gemfile":
			out = append(out, readGemfile(data)...)
		case b == "composer.json":
			out = append(out, readComposer(data)...)
		}
	}
	return out
}

func mapDeps(m map[string]string, dev bool, skip func(string) bool) []DirectDep {
	names := make([]string, 0, len(m))
	for n := range m {
		if skip == nil || !skip(n) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	out := make([]DirectDep, len(names))
	for i, n := range names {
		out[i] = DirectDep{Name: n, Version: m[n], Dev: dev}
	}
	return out
}

func readPackageJSON(data []byte) []DirectDep {
	var pj struct {
		Dependencies, DevDependencies, OptionalDependencies, PeerDependencies map[string]string
	}
	if json.Unmarshal(data, &pj) != nil {
		return nil
	}
	out := mapDeps(pj.Dependencies, false, nil)
	out = append(out, mapDeps(pj.OptionalDependencies, false, nil)...)
	out = append(out, mapDeps(pj.PeerDependencies, false, nil)...)
	return append(out, mapDeps(pj.DevDependencies, true, nil)...)
}

func readGoMod(data []byte) []DirectDep {
	var out []DirectDep
	inBlock := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.Contains(line, "// indirect") {
			continue
		}
		if c, _, ok := strings.Cut(line, "//"); ok {
			line = strings.TrimSpace(c)
		}
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		case !inBlock:
			continue
		}
		if f := strings.Fields(line); len(f) >= 2 {
			out = append(out, DirectDep{Name: strings.Trim(f[0], `"`), Version: f[1]})
		}
	}
	return out
}

func readPom(data []byte) []DirectDep {
	var pom struct {
		Dependencies []struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
			Scope      string `xml:"scope"`
		} `xml:"dependencies>dependency"`
	}
	if xml.Unmarshal(data, &pom) != nil {
		return nil
	}
	var out []DirectDep
	for _, d := range pom.Dependencies {
		if d.GroupID == "" || d.ArtifactID == "" {
			continue
		}
		out = append(out, DirectDep{Name: strings.TrimSpace(d.GroupID) + ":" + strings.TrimSpace(d.ArtifactID),
			Version: strings.TrimSpace(d.Version), Dev: strings.TrimSpace(d.Scope) == "test"})
	}
	return out
}

// tomlDeps reads a TOML dependency table: name = "ver" | {version, package}.
func tomlDeps(t any, dev bool, skip func(string) bool) []DirectDep {
	m, _ := t.(map[string]any)
	names := make([]string, 0, len(m))
	for n := range m {
		if skip == nil || !skip(n) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	var out []DirectDep
	for _, n := range names {
		d := DirectDep{Name: n, Dev: dev}
		switch v := m[n].(type) {
		case string:
			d.Version = v
		case map[string]any:
			d.Version, _ = v["version"].(string)
			if real, ok := v["package"].(string); ok { // Cargo rename
				d.Name = real
			}
		}
		out = append(out, d)
	}
	return out
}

func tomlTable(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		t, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = t[k]
	}
	return cur
}

func readCargo(data []byte) []DirectDep {
	var m map[string]any
	if _, err := toml.Decode(string(data), &m); err != nil {
		return nil
	}
	out := tomlDeps(m["dependencies"], false, nil)
	out = append(out, tomlDeps(m["build-dependencies"], false, nil)...)
	out = append(out, tomlDeps(m["dev-dependencies"], true, nil)...)
	if targets, ok := m["target"].(map[string]any); ok {
		for _, t := range sortedKeys(targets) {
			out = append(out, tomlDeps(tomlTable(m, "target", t, "dependencies"), false, nil)...)
			out = append(out, tomlDeps(tomlTable(m, "target", t, "dev-dependencies"), true, nil)...)
		}
	}
	return out
}

func readPyproject(data []byte) []DirectDep {
	var m map[string]any
	if _, err := toml.Decode(string(data), &m); err != nil {
		return nil
	}
	reqs := func(v any, dev bool) (out []DirectDep) {
		list, _ := v.([]any)
		for _, x := range list {
			if s, ok := x.(string); ok {
				if d, ok := parseRequirement(s); ok {
					d.Dev = dev
					out = append(out, d)
				}
			}
		}
		return out
	}
	// PEP 621.
	out := reqs(tomlTable(m, "project", "dependencies"), false)
	if opt, ok := tomlTable(m, "project", "optional-dependencies").(map[string]any); ok {
		for _, k := range sortedKeys(opt) {
			out = append(out, reqs(opt[k], false)...)
		}
	}
	// PEP 735 dependency groups and uv dev-dependencies are dev-only.
	if groups, ok := m["dependency-groups"].(map[string]any); ok {
		for _, k := range sortedKeys(groups) {
			out = append(out, reqs(groups[k], true)...)
		}
	}
	out = append(out, reqs(tomlTable(m, "tool", "uv", "dev-dependencies"), true)...)
	// Poetry.
	notPython := func(n string) bool { return strings.EqualFold(n, "python") }
	out = append(out, tomlDeps(tomlTable(m, "tool", "poetry", "dependencies"), false, notPython)...)
	out = append(out, tomlDeps(tomlTable(m, "tool", "poetry", "dev-dependencies"), true, notPython)...)
	if groups, ok := tomlTable(m, "tool", "poetry", "group").(map[string]any); ok {
		for _, k := range sortedKeys(groups) {
			out = append(out, tomlDeps(tomlTable(groups, k, "dependencies"), k != "main", notPython)...)
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

var reqName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$`)

// parseRequirement parses a PEP 508 requirement ("requests[socks]>=2; python_version>'3'").
func parseRequirement(s string) (DirectDep, bool) {
	s, _, _ = strings.Cut(s, ";")
	s, _, _ = strings.Cut(s, " #")
	m := reqName.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return DirectDep{}, false
	}
	ver := strings.TrimSpace(m[2])
	if strings.HasPrefix(ver, "@") { // name @ url
		ver = ""
	}
	return DirectDep{Name: m[1], Version: strings.TrimPrefix(ver, "==")}, true
}

func readRequirements(data []byte) []DirectDep {
	var out []DirectDep
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.Contains(line, "://") && !strings.Contains(line, " @ ") {
			continue
		}
		if d, ok := parseRequirement(line); ok {
			out = append(out, d)
		}
	}
	return out
}

var (
	gemLine   = regexp.MustCompile(`^gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?(.*)$`)
	gemDevOpt = regexp.MustCompile(`(?:group|groups)\s*(?::|=>)\s*\[?[^\n]*:(?:development|test)\b`)
	groupLine = regexp.MustCompile(`^group\s+(.+?)\s+do\b`)
	blockOpen = regexp.MustCompile(`\bdo(\s*\|[^|]*\|)?\s*$`)
)

func readGemfile(data []byte) []DirectDep {
	var out []DirectDep
	var stack []bool // per open do-block: is it a dev/test group
	inDev := func() bool { return slices.Contains(stack, true) }
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if c, _, ok := strings.Cut(line, "#"); ok {
			line = strings.TrimSpace(c)
		}
		switch {
		case line == "end":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case groupLine.MatchString(line):
			g := groupLine.FindStringSubmatch(line)[1]
			stack = append(stack, strings.Contains(g, ":development") || strings.Contains(g, ":test"))
		case gemLine.MatchString(line):
			m := gemLine.FindStringSubmatch(line)
			out = append(out, DirectDep{Name: m[1], Version: m[2], Dev: inDev() || gemDevOpt.MatchString(m[3])})
		case blockOpen.MatchString(line): // platforms, source … do
			stack = append(stack, false)
		}
	}
	return out
}

func readComposer(data []byte) []DirectDep {
	var c struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if json.Unmarshal(data, &c) != nil {
		return nil
	}
	platform := func(n string) bool { return n == "php" || !strings.Contains(n, "/") } // php, ext-*, lib-*
	return append(mapDeps(c.Require, false, platform), mapDeps(c.RequireDev, true, platform)...)
}
