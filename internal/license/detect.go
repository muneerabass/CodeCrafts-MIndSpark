package license

import (
	"encoding/json"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/licensecheck"
)

// Detection is the detected project license.
type Detection struct {
	Expr   string // normalised SPDX expression; "" when unknown
	Source string // manifest | license_file | github | unknown
}

// DetectProject finds the project license: manifest license fields
// (package.json, pyproject.toml, Cargo.toml, composer.json, *.gemspec,
// pom.xml), then LICENSE*/COPYING* text via licensecheck, then the GitHub
// license API's SPDX id, else unknown. Root-most files win.
func DetectProject(files map[string][]byte, githubSPDX string) Detection {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		di, dj := strings.Count(names[i], "/"), strings.Count(names[j], "/")
		return di < dj || (di == dj && names[i] < names[j])
	})
	for _, m := range manifestReaders {
		for _, n := range names {
			if m.match(path.Base(n)) {
				if e := normalize(m.read(files[n])); e != "" {
					return Detection{e, "manifest"}
				}
			}
		}
	}
	for _, n := range names {
		b := strings.ToUpper(path.Base(n))
		if !strings.HasPrefix(b, "LICENSE") && !strings.HasPrefix(b, "LICENCE") && !strings.HasPrefix(b, "COPYING") {
			continue
		}
		cov := licensecheck.Scan(files[n])
		if cov.Percent < 75 {
			continue
		}
		var ids []string
		for _, m := range cov.Match {
			if !m.IsURL && !slices.Contains(ids, m.ID) {
				ids = append(ids, m.ID)
			}
		}
		if e := normalize(strings.Join(ids, " AND ")); e != "" {
			return Detection{e, "license_file"}
		}
	}
	if e := normalize(githubSPDX); e != "" {
		return Detection{e, "github"}
	}
	return Detection{"", "unknown"}
}

// normalize returns the canonical SPDX expression, or "" if nothing in it is recognised.
func normalize(raw string) string {
	d := parse(raw)
	if !d.known() {
		return ""
	}
	return d.String()
}

var manifestReaders = []struct {
	match func(base string) bool
	read  func([]byte) string
}{
	{is("package.json"), readJSONLicense("license", "licenses")},
	{is("pyproject.toml"), readPyproject},
	{is("Cargo.toml"), tomlKey("package", "license")},
	{is("composer.json"), readJSONLicense("license")},
	{func(b string) bool { return strings.HasSuffix(b, ".gemspec") }, readGemspec},
	{is("pom.xml"), readPom},
}

func is(name string) func(string) bool { return func(b string) bool { return b == name } }

// readJSONLicense reads a license field that may be a string, {"type": …},
// or an array of either (array = the author offers a choice → OR).
func readJSONLicense(keys ...string) func([]byte) string {
	return func(b []byte) string {
		var m map[string]json.RawMessage
		if json.Unmarshal(b, &m) != nil {
			return ""
		}
		for _, k := range keys {
			if v := jsonLicense(m[k]); v != "" {
				return v
			}
		}
		return ""
	}
}

func jsonLicense(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct{ Type string }
	if json.Unmarshal(raw, &o) == nil && o.Type != "" {
		return o.Type
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		var parts []string
		for _, a := range arr {
			if v := jsonLicense(a); v != "" {
				parts = append(parts, "("+v+")")
			}
		}
		return strings.Join(parts, " OR ")
	}
	return ""
}

var (
	tomlSection = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)
	tomlString  = regexp.MustCompile(`^\s*"([^"]*)"|^\s*'([^']*)'`)
	tomlText    = regexp.MustCompile(`text\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

// tomlKey reads a string key from a TOML section by line scanning
// (ponytail: no multi-line strings or dotted keys; enough for license fields).
func tomlKey(section string, keys ...string) func([]byte) string {
	return func(b []byte) string {
		cur := ""
		for _, line := range strings.Split(string(b), "\n") {
			if m := tomlSection.FindStringSubmatch(line); m != nil {
				cur = strings.TrimSpace(m[1])
				continue
			}
			if cur != section {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok || !slices.Contains(keys, strings.TrimSpace(k)) {
				continue
			}
			if m := tomlString.FindStringSubmatch(v); m != nil {
				return m[1] + m[2]
			}
			if m := tomlText.FindStringSubmatch(v); m != nil { // license = { text = "MIT" }
				return m[1] + m[2]
			}
		}
		return ""
	}
}

// readPyproject: PEP 639 [project] license / license-expression, PEP 621
// license = {text = …} or [project.license] text, then [tool.poetry] license.
func readPyproject(b []byte) string {
	for _, f := range []func([]byte) string{
		tomlKey("project", "license-expression", "license"),
		tomlKey("project.license", "text"),
		tomlKey("tool.poetry", "license"),
	} {
		if v := f(b); v != "" {
			return v
		}
	}
	return ""
}

var (
	gemLicense = regexp.MustCompile(`\.licenses?\s*=\s*(\[[^\]]*\]|"[^"]*"|'[^']*')`)
	gemQuoted  = regexp.MustCompile(`"([^"]*)"|'([^']*)'`)
)

// readGemspec reads spec.license = "MIT" / spec.licenses = ["MIT", "Ruby"] (list → OR).
func readGemspec(b []byte) string {
	m := gemLicense.FindSubmatch(b)
	if m == nil {
		return ""
	}
	var parts []string
	for _, q := range gemQuoted.FindAllSubmatch(m[1], -1) {
		parts = append(parts, "("+string(q[1])+string(q[2])+")")
	}
	return strings.Join(parts, " OR ")
}

var (
	pomLicenses = regexp.MustCompile(`(?s)<licenses>(.*?)</licenses>`)
	pomName     = regexp.MustCompile(`(?s)<name>\s*(.*?)\s*</name>`)
)

// readPom reads <licenses><license><name> (several licenses → OR, Maven's convention for dual licensing).
func readPom(b []byte) string {
	m := pomLicenses.FindSubmatch(b)
	if m == nil {
		return ""
	}
	var parts []string
	for _, n := range pomName.FindAllSubmatch(m[1], -1) {
		if e := normalize(string(n[1])); e != "" {
			parts = append(parts, "("+e+")")
		}
	}
	return strings.Join(parts, " OR ")
}
