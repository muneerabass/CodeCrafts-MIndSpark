package httpapi

import (
	"context"
	"testing"
)

func TestFixes(t *testing.T) {
	ctx := context.Background()
	_, err := tdb.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain) VALUES ('tfx','fx.test'), ('tfx2','fx2.test');
INSERT INTO projects (id, tenant_id, source, name, url, gh_repo_id) VALUES ('pfx','tfx','github','acme/web','', 601), ('pfx2','tfx2','github','o/x','', 602);
INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('vfx','tfx','pfx','main');
INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status) VALUES ('sfx','tfx','pfx','vfx','push','success');
UPDATE project_versions SET last_scan_id='sfx' WHERE id='vfx';
INSERT INTO components (id, tenant_id, ecosystem, name, version, purl) VALUES
  ('cl','tfx','npm','lodash','4.17.15','pkg:npm/lodash@4.17.15'), ('cy','tfx','npm','left-pad','1.0.0','pkg:npm/left-pad@1.0.0'),
  ('cg','tfx','Go','golang.org/x/net','0.1.0','pkg:golang/golang.org/x/net@0.1.0');
INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path, direct) VALUES
  ('tfx','vfx','cl','web/package-lock.json',true), ('tfx','vfx','cy','web/package-lock.json',false), ('tfx','vfx','cg','yarn.lock',true);
INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk, fixed_in) VALUES
  ('tfx','cl','GHSA-a','HIGH','4.17.19'), ('tfx','cl','GHSA-b','CRITICAL','4.17.21'), ('tfx','cy','GHSA-c','LOW',NULL),
  ('tfx','cg','GHSA-d','HIGH','0.7.0');`)
	if err != nil {
		t.Fatal(err)
	}
	member, owner, other := token("tfx", "member", false), token("tfx", "owner", false), token("tfx2", "owner", false)
	lodash := map[string]string{"ecosystem": "npm", "name": "lodash", "version": "4.17.15", "manifest_path": "web/package-lock.json"}

	expect(t, do(t, "POST", "/api/v1/projects/pfx/fixes", member, lodash), 403)
	expect(t, do(t, "POST", "/api/v1/projects/pfx/fixes", other, lodash), 422) // other tenant sees no such package
	a := expect(t, do(t, "POST", "/api/v1/projects/pfx/fixes", owner, lodash), 202).body
	if a["status"] != "queued" || a["to_version"] != "4.17.21" || a["command"] != "npm install lodash@4.17.21" {
		t.Fatalf("create %v", a)
	}
	if b := expect(t, do(t, "POST", "/api/v1/projects/pfx/fixes", owner, lodash), 202).body; b["status"] != "exists" || b["id"] != a["id"] {
		t.Fatalf("duplicate %v", b)
	}
	// No fixed version → 422; unsupported lockfile → command only.
	expect(t, do(t, "POST", "/api/v1/projects/pfx/fixes", owner, map[string]string{"ecosystem": "npm", "name": "left-pad", "version": "1.0.0", "manifest_path": "web/package-lock.json"}), 422)
	u := expect(t, do(t, "POST", "/api/v1/projects/pfx/fixes", owner, map[string]string{"ecosystem": "Go", "name": "golang.org/x/net", "version": "0.1.0", "manifest_path": "yarn.lock"}), 202).body
	if u["status"] != "unsupported" || u["command"] == "" {
		t.Fatalf("unsupported %v", u)
	}

	l := expect(t, do(t, "GET", "/api/v1/fixes?project_id=pfx", member, nil), 200).body
	items := listOf(l["items"])
	if l["total"].(float64) != 1 || mapOf(items[0])["to_version"] != "4.17.21" || len(listOf(mapOf(items[0])["advisories"])) != 2 {
		t.Fatalf("list %v", l)
	}
	if expect(t, do(t, "GET", "/api/v1/fixes", other, nil), 200).body["total"].(float64) != 0 {
		t.Fatal("other tenant sees fixes")
	}

	// Settings: defaults, validation, round trip.
	s := expect(t, do(t, "GET", "/api/v1/settings/fixes", member, nil), 200).body
	if s["auto"] != false || s["max_open"].(float64) != 5 {
		t.Fatalf("defaults %v", s)
	}
	expect(t, do(t, "PUT", "/api/v1/settings/fixes", member, map[string]any{"auto": true}), 403)
	expect(t, do(t, "PUT", "/api/v1/settings/fixes", owner, map[string]any{"auto": true, "levels": []string{"urgent"}, "max_open": 5}), 400)
	s = expect(t, do(t, "PUT", "/api/v1/settings/fixes", owner, map[string]any{"auto": true, "levels": []string{"critical", "high"}, "kev": true, "max_open": 3}), 200).body
	if s["auto"] != true || s["max_open"].(float64) != 3 || len(listOf(s["levels"])) != 2 {
		t.Fatalf("saved %v", s)
	}
}
