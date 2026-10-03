package scan

import (
	"fmt"
	"slices"
	"testing"

	"github.com/safedep/vet/pkg/models"
)

func depsString(ds []DirectDep) []string {
	var out []string
	for _, d := range ds {
		s := d.Name
		if d.Version != "" {
			s += "@" + d.Version
		}
		if d.Dev {
			s += " (dev)"
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func TestReadDirectDeps(t *testing.T) {
	cases := []struct {
		eco, file, content string
		want               []string
	}{
		{models.EcosystemNpm, "web/package.json",
			`{"dependencies":{"express":"^4.18.0"},"devDependencies":{"jest":"^29"},"optionalDependencies":{"fsevents":"2"},"peerDependencies":{"react":">=18"}}`,
			[]string{"express@^4.18.0", "fsevents@2", "jest@^29 (dev)", "react@>=18"}},
		{models.EcosystemGo, "go.mod", "module x\n\ngo 1.22\n\nrequire github.com/a/b v1.0.0\nrequire (\n\tgithub.com/c/d v1.2.0\n\tgithub.com/e/f v0.1.0 // indirect\n\tgolang.org/x/sync v0.7.0 // pinned\n)\nreplace (\n\tgithub.com/c/d => ../d\n)\n",
			[]string{"github.com/a/b@v1.0.0", "github.com/c/d@v1.2.0", "golang.org/x/sync@v0.7.0"}},
		{models.EcosystemMaven, "pom.xml", `<project><dependencyManagement><dependencies><dependency><groupId>m</groupId><artifactId>managed</artifactId></dependency></dependencies></dependencyManagement>
			<dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>6.1.0</version></dependency>
			<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency></dependencies></project>`,
			[]string{"junit:junit@4.13 (dev)", "org.springframework:spring-core@6.1.0"}},
		{models.EcosystemCargo, "Cargo.toml", "[package]\nname=\"x\"\n[dependencies]\nserde = \"1.0\"\ntokio = { version = \"1\", features = [\"full\"] }\nrenamed = { package = \"real-crate\", version = \"0.2\" }\n[dev-dependencies]\ncriterion = \"0.5\"\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n",
			[]string{"criterion@0.5 (dev)", "libc@0.2", "real-crate@0.2", "serde@1.0", "tokio@1"}},
		{models.EcosystemPyPI, "pyproject.toml", "[project]\ndependencies = [\"requests[socks]>=2.31; python_version>'3.8'\", \"PyYAML==6.0\"]\n[project.optional-dependencies]\nfast = [\"orjson\"]\n[dependency-groups]\ndev = [\"pytest>=8\"]\n",
			[]string{"PyYAML@6.0", "orjson", "pytest@>=8 (dev)", "requests@>=2.31"}},
		{models.EcosystemPyPI, "pyproject.toml", "[tool.poetry.dependencies]\npython = \"^3.11\"\nfastapi = \"^0.110\"\n[tool.poetry.group.dev.dependencies]\nblack = \"*\"\n",
			[]string{"black@* (dev)", "fastapi@^0.110"}},
		{models.EcosystemPyPI, "requirements-dev.txt", "# comment\n-r base.txt\n-e .\nflask==3.0.0  # web\nDjango>=4\nmypkg @ https://x/y.whl\nhttps://example.com/pkg.tar.gz\n",
			[]string{"Django@>=4", "flask@3.0.0", "mypkg"}},
		{models.EcosystemRubyGems, "Gemfile", "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem 'pry', group: :development\ngroup :development, :test do\n  gem 'rspec'\nend\ngroup :production do\n  gem 'pg'\nend\n",
			[]string{"pg", "pry (dev)", "rails@~> 7.1", "rspec (dev)"}},
		{models.EcosystemPackagist, "composer.json", `{"require":{"php":">=8.1","ext-json":"*","laravel/framework":"^11.0"},"require-dev":{"phpunit/phpunit":"^10"}}`,
			[]string{"laravel/framework@^11.0", "phpunit/phpunit@^10 (dev)"}},
	}
	for _, c := range cases {
		got := depsString(ReadDirectDeps(c.eco, map[string][]byte{c.file: []byte(c.content)}))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q want %q", c.file, got, c.want)
		}
	}
	// Other ecosystems' manifests are ignored; package.json beats the lock root.
	files := map[string][]byte{"package.json": []byte(`{"dependencies":{"a":"1"}}`), "go.mod": []byte("require x v1\n"),
		"package-lock.json": []byte(`{"packages":{"":{"dependencies":{"b":"1"}}}}`)}
	if got := fmt.Sprint(depsString(ReadDirectDeps(models.EcosystemNpm, files))); got != "[a@1]" {
		t.Fatalf("npm deps %s", got)
	}
}
