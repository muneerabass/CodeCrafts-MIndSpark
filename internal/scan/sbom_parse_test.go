package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/sbom"
)

// SBOM uploads (container images, other tools) are parsed through vet's bom-cyclonedx / bom-spdx readers.
func TestParseSBOM(t *testing.T) {
	d := sbom.Doc{Project: "img", Version: "latest", Serial: "x", Created: time.Now(), Components: []sbom.Component{
		{ID: "1", Ecosystem: "npm", Name: "lodash", Version: "4.17.15", PURL: "pkg:npm/lodash@4.17.15"},
		{ID: "2", Ecosystem: "PyPI", Name: "requests", Version: "2.25.0", PURL: "pkg:pypi/requests@2.25.0"},
		{ID: "3", Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.1.0", PURL: "pkg:golang/golang.org/x/net@v0.1.0"},
	}}
	dir := t.TempDir()
	for name, build := range map[string]func(sbom.Doc) ([]byte, error){"image.cdx.json": sbom.CycloneDX, "image.spdx.json": sbom.SPDX} {
		b, err := build(d)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		ms, err := Parse([]Lockfile{{Path: p, RepoPath: name, As: SBOMFormat(name)}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := map[string]string{}
		for _, m := range ms {
			for _, pkg := range m.GetPackages() {
				got[string(pkg.Ecosystem)+"/"+pkg.GetName()] = pkg.GetVersion()
			}
		}
		if got["npm/lodash"] != "4.17.15" || got["PyPI/requests"] != "2.25.0" || len(got) != 3 {
			t.Fatalf("%s: %v", name, got)
		}
		if IsManifest("sub/"+name) || SBOMFormat("sub/"+name) == "" {
			t.Fatalf("%s: SBOMs are upload-only, never picked from a repository tree", name)
		}
	}
}

func TestParseCycloneDX17(t *testing.T) {
	b, _ := sbom.CycloneDX(sbom.Doc{Project: "img", Version: "1", Serial: "s", Created: time.Now(),
		Components: []sbom.Component{{ID: "1", Ecosystem: "npm", Name: "lodash", Version: "4.17.15", PURL: "pkg:npm/lodash@4.17.15"}}})
	b = []byte(strings.Replace(string(b), `"specVersion": "1.6"`, `"specVersion": "1.7"`, 1))
	p := filepath.Join(t.TempDir(), "image.cdx.json")
	os.WriteFile(p, b, 0o600)
	ms, err := Parse([]Lockfile{{Path: p, RepoPath: "image.cdx.json", As: SBOMFormat(p)}})
	if err != nil || len(ms) != 1 || len(ms[0].GetPackages()) != 1 {
		t.Fatalf("%v %v", ms, err)
	}
}
