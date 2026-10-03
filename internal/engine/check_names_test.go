package engine

import "testing"

func TestProjectNames(t *testing.T) {
	got := projectNames([]CheckFile{
		{"package.json", `{"name":"@acme/web","dependencies":{"x":"1"}}`},
		{"pyproject.toml", "[build-system]\nrequires = [\"hatchling\"]\nname = \"not-this\"\n\n[project]\nname = \"Guard-Py\"\nversion = \"0.1.0\"\n"},
		{"sub/Cargo.toml", "[package]\nname = \"my-crate\"\n\n[dependencies]\nserde = \"1\"\n"},
		{"poetry/pyproject.toml", "[tool.poetry]\nname = 'poet'\n"},
	})
	for _, n := range []string{"@acme/web", "guard-py", "my-crate", "poet"} {
		if !got[n] {
			t.Errorf("missing %s in %v", n, got)
		}
	}
	if got["not-this"] || got["serde"] {
		t.Errorf("wrong names: %v", got)
	}
}
