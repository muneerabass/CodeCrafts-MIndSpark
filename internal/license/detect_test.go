package license

import (
	"os"
	"testing"
)

func TestDetectProject(t *testing.T) {
	mit, _ := os.ReadFile("testdata/LICENSE-MIT")
	apache, _ := os.ReadFile("testdata/LICENSE-Apache-2.0")
	for _, c := range []struct {
		name  string
		files map[string]string
		gh    string
		want  Detection
	}{
		{"package.json string", map[string]string{"package.json": `{"name":"x","license":"MIT"}`}, "", Detection{"MIT", "manifest"}},
		{"package.json legacy object", map[string]string{"package.json": `{"license":{"type":"ISC","url":"x"}}`}, "", Detection{"ISC", "manifest"}},
		{"package.json legacy array", map[string]string{"package.json": `{"licenses":[{"type":"MIT"},{"type":"Apache-2.0"}]}`}, "", Detection{"MIT OR Apache-2.0", "manifest"}},
		{"pyproject PEP 639", map[string]string{"pyproject.toml": "[project]\nname = \"x\"\nlicense = \"Apache-2.0\"\n"}, "", Detection{"Apache-2.0", "manifest"}},
		{"pyproject table text", map[string]string{"pyproject.toml": "[project]\nlicense = { text = \"BSD-3-Clause\" }\n"}, "", Detection{"BSD-3-Clause", "manifest"}},
		{"pyproject license-expression", map[string]string{"pyproject.toml": "[project]\nlicense-expression = 'MIT OR Apache-2.0'\n"}, "", Detection{"MIT OR Apache-2.0", "manifest"}},
		{"pyproject [project.license]", map[string]string{"pyproject.toml": "[project.license]\ntext = \"GPL-3.0\"\n"}, "", Detection{"GPL-3.0-only", "manifest"}},
		{"pyproject poetry", map[string]string{"pyproject.toml": "[tool.poetry]\nlicense = \"MIT\"\n"}, "", Detection{"MIT", "manifest"}},
		{"Cargo", map[string]string{"Cargo.toml": "[dependencies]\nlicense = \"no\"\n[package]\nname = \"x\"\nlicense = \"MIT/Apache-2.0\"\n"}, "", Detection{"MIT OR Apache-2.0", "manifest"}},
		{"composer string", map[string]string{"composer.json": `{"license":"GPL-2.0-or-later"}`}, "", Detection{"GPL-2.0-or-later", "manifest"}},
		{"composer array", map[string]string{"composer.json": `{"license":["LGPL-2.1-only","GPL-3.0-or-later"]}`}, "", Detection{"LGPL-2.1-only OR GPL-3.0-or-later", "manifest"}},
		{"gemspec", map[string]string{"x.gemspec": "Gem::Specification.new do |s|\n  s.licenses = ['MIT', \"Ruby\"]\nend\n"}, "", Detection{"MIT OR Ruby", "manifest"}},
		{"gemspec single", map[string]string{"x.gemspec": "spec.license = \"BSD-2-Clause\"\n"}, "", Detection{"BSD-2-Clause", "manifest"}},
		{"pom", map[string]string{"pom.xml": "<project><licenses><license><name>The Apache Software License, Version 2.0</name><url>u</url></license></licenses></project>"}, "", Detection{"Apache-2.0", "manifest"}},
		{"MIT LICENSE text", map[string]string{"LICENSE": string(mit)}, "", Detection{"MIT", "license_file"}},
		{"Apache LICENSE text", map[string]string{"LICENSE.txt": string(apache)}, "", Detection{"Apache-2.0", "license_file"}},
		{"manifest beats LICENSE", map[string]string{"LICENSE": string(mit), "package.json": `{"license":"ISC"}`}, "", Detection{"ISC", "manifest"}},
		{"unknown manifest falls through", map[string]string{"package.json": `{"license":"UNLICENSED"}`, "COPYING": string(mit)}, "", Detection{"MIT", "license_file"}},
		{"partial LICENSE ignored → github", map[string]string{"LICENSE": "Copyright me. All rights reserved. " + string(mit[:120])}, "BSD-3-Clause", Detection{"BSD-3-Clause", "github"}},
		{"github NOASSERTION", nil, "NOASSERTION", Detection{"", "unknown"}},
		{"github other", nil, "other", Detection{"", "unknown"}},
		{"root wins over nested", map[string]string{"sub/package.json": `{"license":"GPL-3.0"}`, "package.json": `{"license":"MIT"}`}, "", Detection{"MIT", "manifest"}},
	} {
		files := map[string][]byte{}
		for k, v := range c.files {
			files[k] = []byte(v)
		}
		if got := DetectProject(files, c.gh); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}
