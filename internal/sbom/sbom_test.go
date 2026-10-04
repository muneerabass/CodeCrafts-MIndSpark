package sbom

import (
	"bytes"
	"strings"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/spdx/tools-golang/json"
)

var doc = Doc{
	Project: "acme/web", Version: "main", Serial: "01JB8A0000000000000000002", Created: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC),
	Components: []Component{
		{ID: "c1", Ecosystem: "npm", Name: "express", Version: "4.17.1", PURL: "pkg:npm/express@4.17.1", Licenses: []string{"MIT"}, Direct: true, Manifests: []string{"package-lock.json"}},
		{ID: "c2", Ecosystem: "npm", Name: "qs", Version: "6.7.0", PURL: "pkg:npm/qs@6.7.0", Licenses: []string{"BSD-3-Clause"}, Manifests: []string{"package-lock.json"}},
		{ID: "c3", Ecosystem: "npm", Name: "odd", Version: "1.0.0", PURL: "pkg:npm/odd@1.0.0", Licenses: []string{"MIT OR Apache-2.0", "Custom Corp License"}, Dev: true, Direct: true},
		{ID: "c4", Ecosystem: "npm", Name: "inhouse", Version: "2.0.0", PURL: "pkg:npm/inhouse@2.0.0", Licenses: []string{"Custom Corp License"}},
	},
	Edges: []Edge{{"", "c1"}, {"", "c3"}, {"c1", "c2"}, {"c1", "c2"}},
	Vulns: []Vuln{{ComponentID: "c2", ID: "GHSA-hrpp-h998-j3pp", Risk: "HIGH", FixedIn: "6.7.3"}},
}

func TestCycloneDX(t *testing.T) {
	b, err := CycloneDX(doc)
	if err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(b), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatal(err)
	}
	if bom.SpecVersion != cdx.SpecVersion1_6 || len(*bom.Components) != 4 || (*(*bom.Components)[3].Licenses)[0].License.Name != "Custom Corp License" || bom.Metadata.Component.Name != "acme/web" || !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Fatalf("bom %+v", bom.Metadata)
	}
	deps := map[string][]string{}
	for _, d := range *bom.Dependencies {
		if d.Dependencies != nil {
			deps[d.Ref] = *d.Dependencies
		}
	}
	if len(deps["app:acme/web"]) != 2 || len(deps["pkg:npm/express@4.17.1"]) != 1 || deps["pkg:npm/express@4.17.1"][0] != "pkg:npm/qs@6.7.0" {
		t.Fatalf("deps %v", deps)
	}
	v := (*bom.Vulnerabilities)[0]
	if v.ID != "GHSA-hrpp-h998-j3pp" || (*v.Affects)[0].Ref != "pkg:npm/qs@6.7.0" || (*v.Ratings)[0].Severity != cdx.SeverityHigh || v.Recommendation == "" {
		t.Fatalf("vuln %+v", v)
	}
	odd := (*bom.Components)[2]
	ls := *odd.Licenses
	if odd.Scope != cdx.ScopeOptional || len(ls) != 1 || ls[0].Expression != "MIT OR Apache-2.0" || (*bom.Components)[0].Licenses == nil || (*(*bom.Components)[0].Licenses)[0].License.ID != "MIT" {
		t.Fatalf("odd %+v %+v", odd, ls)
	}
}

func TestSPDXLicense(t *testing.T) {
	for in, want := range map[string]string{"": "NOASSERTION", "MIT": "MIT", "MIT|GPL-2.0-only OR MIT": "MIT AND (GPL-2.0-only OR MIT)", "Custom Corp": "NOASSERTION"} {
		var ls []string
		if in != "" {
			ls = strings.Split(in, "|")
		}
		if got := spdxLicense(ls); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestSPDX(t *testing.T) {
	b, err := SPDX(doc)
	if err != nil {
		t.Fatal(err)
	}
	d, err := json.Read(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if d.SPDXVersion != "SPDX-2.3" || len(d.Packages) != 5 || d.DocumentName != "acme/web@main" {
		t.Fatalf("doc %s %d", d.SPDXVersion, len(d.Packages))
	}
	var depends int
	for _, r := range d.Relationships {
		if r.Relationship == "DEPENDS_ON" {
			depends++
		}
	}
	if depends != 3 { // root→express, root→odd, express→qs (duplicate edge dropped)
		t.Fatalf("relationships %d", depends)
	}
	if d.Packages[3].PackageLicenseDeclared != "MIT OR Apache-2.0" || d.Packages[1].PackageExternalReferences[0].Locator != "pkg:npm/express@4.17.1" {
		t.Fatalf("packages %+v %+v", d.Packages[3], d.Packages[1])
	}
}

// TestCycloneDXSchema validates the output against the official 1.6 JSON schema shipped with cyclonedx-go.
func TestCycloneDXSchema(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/CycloneDX/cyclonedx-go").Output()
	if err != nil {
		t.Skip("go list:", err)
	}
	dir := filepath.Join(strings.TrimSpace(string(out)), "schema")
	c := jsonschema.NewCompiler()
	for f, local := range map[string]string{"jsf-0.82.schema.json": "jsf-0.82.schemax.json", "spdx.schema.json": "spdx.schema.json"} {
		fh, err := os.Open(filepath.Join(dir, local))
		if err != nil {
			t.Fatal(err)
		}
		v, err := jsonschema.UnmarshalJSON(fh)
		fh.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource("http://cyclonedx.org/schema/"+f, v); err != nil {
			t.Fatal(err)
		}
	}
	sch, err := c.Compile(filepath.Join(dir, "bom-1.6.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := CycloneDX(doc)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("schema: %v", err)
	}
}
