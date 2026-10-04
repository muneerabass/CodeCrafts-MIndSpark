package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSBOM(t *testing.T) {
	ctx := context.Background()
	_, err := tdb.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain) VALUES ('tsb','sb.test'), ('tsb2','sb2.test');
INSERT INTO projects (id, tenant_id, source, name, url) VALUES ('psb','tsb','cli','acme/web','');
INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('vsb','tsb','psb','main');
INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status) VALUES ('ssb','tsb','psb','vsb','cli','success');
UPDATE project_versions SET last_scan_id='ssb' WHERE id='vsb';
INSERT INTO components (id, tenant_id, ecosystem, name, version, purl, licenses) VALUES
  ('sb1','tsb','npm','express','4.17.1','pkg:npm/express@4.17.1','{MIT}'), ('sb2','tsb','npm','qs','6.7.0','pkg:npm/qs@6.7.0','{BSD-3-Clause}');
INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path, direct, depth) VALUES
  ('tsb','vsb','sb1','package-lock.json',true,1), ('tsb','vsb','sb2','package-lock.json',false,2);
INSERT INTO project_version_dependencies (tenant_id, project_version_id, manifest_path, parent_component_id, child_component_id) VALUES
  ('tsb','vsb','package-lock.json',NULL,'sb1'), ('tsb','vsb','package-lock.json','sb1','sb2');
INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk, fixed_in) VALUES ('tsb','sb2','GHSA-hrpp-h998-j3pp','HIGH','6.7.3');`)
	if err != nil {
		t.Fatal(err)
	}
	member := token("tsb", "member", false)
	res := do(t, "GET", "/api/v1/projects/psb/sbom", member, nil)
	expect(t, res, 200)
	var bom map[string]any
	if err := json.Unmarshal([]byte(res.raw), &bom); err != nil {
		t.Fatal(err)
	}
	if bom["specVersion"] != "1.6" || len(listOf(bom["components"])) != 2 || len(listOf(bom["vulnerabilities"])) != 1 || len(listOf(bom["dependencies"])) != 3 {
		t.Fatalf("cyclonedx %s", res.raw[:300])
	}
	if cd := res.header.Get("Content-Disposition"); cd != `attachment; filename="acme_web-main.cdx.json"` {
		t.Fatalf("disposition %q", cd)
	}
	spdx := expect(t, do(t, "GET", "/api/v1/projects/psb/sbom?format=spdx&version=main", member, nil), 200).raw
	if !strings.Contains(spdx, `"spdxVersion": "SPDX-2.3"`) || strings.Count(spdx, `"DEPENDS_ON"`) != 2 {
		t.Fatalf("spdx %s", spdx)
	}
	expect(t, do(t, "GET", "/api/v1/projects/psb/sbom?format=xml", member, nil), 400)
	expect(t, do(t, "GET", "/api/v1/projects/psb/sbom", token("tsb2", "member", false), nil), 404)

	// CI with an API key, by project name.
	key := apiKey(t, "tsb")
	if b := expect(t, do(t, "GET", "/v1/sbom?project=acme/web&branch=main", key, nil), 200).raw; !strings.Contains(b, `"bomFormat": "CycloneDX"`) {
		t.Fatalf("api key sbom %s", b[:200])
	}
	expect(t, do(t, "GET", "/v1/sbom", key, nil), 400)
}
