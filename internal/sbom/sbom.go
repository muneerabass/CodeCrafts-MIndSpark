// Package sbom writes a project version's dependency inventory as a
// CycloneDX 1.6 or SPDX 2.3 JSON document.
package sbom

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// Component is one package in the inventory.
type Component struct {
	ID, Ecosystem, Name, Version, PURL string
	Licenses                           []string
	Direct, Dev                        bool
	Manifests                          []string
}

// Edge is a dependency edge; Parent "" is the project itself.
type Edge struct{ Parent, Child string }

// Vuln is a known vulnerability of a component.
type Vuln struct{ ComponentID, ID, Risk, FixedIn string }

// Doc is everything an SBOM contains.
type Doc struct {
	Project, Version, Serial string // Serial: unique id for this document (scan id)
	Created                  time.Time
	Components               []Component
	Edges                    []Edge
	Vulns                    []Vuln
}

const tool = "depguard"

// licenses maps stored licenses to CycloneDX: one entry per plain license (SPDX
// id or free-text name), or, when any is an expression, a single combined SPDX
// expression (CycloneDX does not allow mixing the two forms).
func licenses(ls []string) *cdx.Licenses {
	if len(ls) == 0 {
		return nil
	}
	var out cdx.Licenses
	for _, l := range ls {
		if strings.ContainsAny(l, " ()") {
			if _, err := spdxexp.ExtractLicenses(l); err == nil {
				if e := spdxLicense(ls); e != "NOASSERTION" {
					return &cdx.Licenses{{Expression: e}}
				}
			}
		}
		if ok, _ := spdxexp.ValidateLicenses([]string{l}); ok {
			out = append(out, cdx.LicenseChoice{License: &cdx.License{ID: l}})
		} else {
			out = append(out, cdx.LicenseChoice{License: &cdx.License{Name: l}})
		}
	}
	return &out
}

// CycloneDX renders d as CycloneDX 1.6 JSON with dependencies and vulnerabilities.
func CycloneDX(d Doc) ([]byte, error) {
	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + uuidFrom(d.Serial)
	app := "app:" + d.Project
	bom.Metadata = &cdx.Metadata{
		Timestamp: d.Created.UTC().Format(time.RFC3339),
		Tools:     &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: tool}}},
		Component: &cdx.Component{BOMRef: app, Type: cdx.ComponentTypeApplication, Name: d.Project, Version: d.Version},
	}
	ref := map[string]string{} // component id → bom-ref
	comps := make([]cdx.Component, 0, len(d.Components))
	for _, c := range d.Components {
		r := c.PURL
		if r == "" {
			r = c.Ecosystem + "/" + c.Name + "@" + c.Version
		}
		ref[c.ID] = r
		cc := cdx.Component{BOMRef: r, Type: cdx.ComponentTypeLibrary, Name: c.Name, Version: c.Version, PackageURL: c.PURL, Scope: cdx.ScopeRequired}
		if c.Dev {
			cc.Scope = cdx.ScopeOptional
		}
		cc.Licenses = licenses(c.Licenses)
		var props []cdx.Property
		for _, l := range c.Licenses {
			props = append(props, cdx.Property{Name: "depguard:license", Value: l})
		}
		for _, m := range c.Manifests {
			props = append(props, cdx.Property{Name: "depguard:manifest", Value: m})
		}
		props = append(props, cdx.Property{Name: "depguard:direct", Value: fmt.Sprint(c.Direct)})
		cc.Properties = &props
		comps = append(comps, cc)
	}
	bom.Components = &comps

	children := map[string][]string{}
	for _, e := range d.Edges {
		p := app
		if e.Parent != "" {
			p = ref[e.Parent]
		}
		if c := ref[e.Child]; p != "" && c != "" && !contains(children[p], c) {
			children[p] = append(children[p], c)
		}
	}
	if len(d.Edges) == 0 { // no graph: direct dependencies hang off the app
		for _, c := range d.Components {
			if c.Direct {
				children[app] = append(children[app], ref[c.ID])
			}
		}
	}
	deps := []cdx.Dependency{{Ref: app, Dependencies: ptr(children[app])}}
	for _, c := range d.Components {
		dep := cdx.Dependency{Ref: ref[c.ID]}
		if ch := children[ref[c.ID]]; len(ch) > 0 {
			dep.Dependencies = ptr(ch)
		}
		deps = append(deps, dep)
	}
	bom.Dependencies = &deps

	if len(d.Vulns) > 0 {
		vs := make([]cdx.Vulnerability, 0, len(d.Vulns))
		for _, v := range d.Vulns {
			vv := cdx.Vulnerability{BOMRef: v.ID + "/" + ref[v.ComponentID], ID: v.ID,
				Source:  &cdx.Source{Name: "OSV", URL: "https://osv.dev/vulnerability/" + v.ID},
				Ratings: &[]cdx.VulnerabilityRating{{Severity: severity(v.Risk), Method: cdx.ScoringMethodOther}},
				Affects: &[]cdx.Affects{{Ref: ref[v.ComponentID]}}}
			if v.FixedIn != "" {
				vv.Recommendation = "Upgrade to " + v.FixedIn + " or later."
			}
			vs = append(vs, vv)
		}
		bom.Vulnerabilities = &vs
	}
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func severity(risk string) cdx.Severity {
	switch strings.ToUpper(risk) {
	case "CRITICAL":
		return cdx.SeverityCritical
	case "HIGH":
		return cdx.SeverityHigh
	case "MEDIUM":
		return cdx.SeverityMedium
	case "LOW":
		return cdx.SeverityLow
	}
	return cdx.SeverityUnknown
}

// SPDX renders d as SPDX 2.3 JSON with DEPENDS_ON relationships.
func SPDX(d Doc) ([]byte, error) {
	doc := &spdx.Document{
		SPDXVersion:       spdx.Version,
		DataLicense:       spdx.DataLicense,
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      d.Project + "@" + d.Version,
		DocumentNamespace: "https://spdx.depguard.dev/" + safeID(d.Project) + "/" + uuidFrom(d.Serial),
		CreationInfo: &spdx.CreationInfo{Created: d.Created.UTC().Format(time.RFC3339),
			Creators: []common.Creator{{CreatorType: "Tool", Creator: tool}}},
	}
	root := common.ElementID("Root")
	doc.Packages = append(doc.Packages, &spdx.Package{PackageName: d.Project, PackageSPDXIdentifier: root, PackageVersion: d.Version,
		PackageDownloadLocation: "NOASSERTION", PrimaryPackagePurpose: "APPLICATION"})
	ids := map[string]common.ElementID{}
	for i, c := range d.Components {
		id := common.ElementID(fmt.Sprintf("Package-%d", i+1))
		ids[c.ID] = id
		p := &spdx.Package{PackageName: c.Name, PackageSPDXIdentifier: id, PackageVersion: c.Version, PackageDownloadLocation: "NOASSERTION",
			PackageLicenseConcluded: "NOASSERTION", PackageLicenseDeclared: spdxLicense(c.Licenses), PackageCopyrightText: "NOASSERTION",
			PrimaryPackagePurpose: "LIBRARY"}
		if c.PURL != "" {
			p.PackageExternalReferences = []*spdx.PackageExternalReference{{Category: "PACKAGE-MANAGER", RefType: "purl", Locator: c.PURL}}
		}
		doc.Packages = append(doc.Packages, p)
	}
	rel := func(a, b common.ElementID, t string) {
		doc.Relationships = append(doc.Relationships, &spdx.Relationship{RefA: common.MakeDocElementID("", string(a)), RefB: common.MakeDocElementID("", string(b)), Relationship: t})
	}
	rel("DOCUMENT", root, "DESCRIBES")
	seen := map[[2]common.ElementID]bool{}
	add := func(a, b common.ElementID) {
		if a != "" && b != "" && !seen[[2]common.ElementID{a, b}] {
			seen[[2]common.ElementID{a, b}] = true
			rel(a, b, "DEPENDS_ON")
		}
	}
	for _, e := range d.Edges {
		p := root
		if e.Parent != "" {
			p = ids[e.Parent]
		}
		add(p, ids[e.Child])
	}
	if len(d.Edges) == 0 {
		for _, c := range d.Components {
			if c.Direct {
				add(root, ids[c.ID])
			}
		}
	}
	var buf bytes.Buffer
	if err := json.Write(doc, &buf, json.Indent("  ")); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// spdxLicense joins licenses into a valid SPDX expression, or NOASSERTION.
func spdxLicense(ls []string) string {
	var ok []string
	for _, l := range ls {
		if _, err := spdxexp.ExtractLicenses(l); err == nil {
			ok = append(ok, l)
		}
	}
	switch len(ok) {
	case 0:
		return "NOASSERTION"
	case 1:
		return ok[0]
	}
	for i, l := range ok {
		if strings.Contains(l, " ") {
			ok[i] = "(" + l + ")"
		}
	}
	return strings.Join(ok, " AND ")
}

func safeID(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			return r
		}
		return '-'
	}, s)
}

// uuidFrom derives a stable UUID-shaped string from an id (a ULID scan id).
func uuidFrom(id string) string {
	h := fmt.Sprintf("%032x", []byte(id))
	if len(h) > 32 {
		h = h[:32]
	}
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func ptr(s []string) *[]string {
	if len(s) == 0 {
		return nil
	}
	return &s
}
