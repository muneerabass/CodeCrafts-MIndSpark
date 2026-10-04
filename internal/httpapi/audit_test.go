package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAuditLog(t *testing.T) {
	ctx := context.Background()
	if _, err := tdb.Owner.Exec(ctx, `INSERT INTO tenant_settings (tenant_id, domain) VALUES ('tau','au.test'), ('tau2','au2.test')`); err != nil {
		t.Fatal(err)
	}
	member, owner := token("tau", "member", false), token("tau", "owner", false)
	expect(t, do(t, "PUT", "/api/v1/settings/sla", owner, map[string]int{"critical": 5, "high": 30, "medium": 90}), 200)
	expect(t, do(t, "PUT", "/api/v1/settings/sla", owner, map[string]int{"critical": 999}), 400) // failed: not logged
	expect(t, do(t, "GET", "/api/v1/settings/sla", owner, nil), 200)                          // reads: not logged
	expect(t, do(t, "POST", "/api/v1/api-keys", owner, map[string]string{"name": "CI deploy"}), 201)
	expect(t, do(t, "POST", "/api/v1/audit", owner, map[string]any{"action": "web:member.role", "target_type": "member", "target_id": "u-2", "details": map[string]string{"role": "admin"}}), 201)
	expect(t, do(t, "POST", "/api/v1/audit", owner, map[string]any{"action": "PUT /policy"}), 400) // web actions only

	expect(t, do(t, "GET", "/api/v1/audit-log", member, nil), 403) // admins and owners only
	var l map[string]any
	for i := 0; i < 20; i++ { // writes are synchronous, but allow for slow CI
		if l = expect(t, do(t, "GET", "/api/v1/audit-log", owner, nil), 200).body; l["total"].(float64) == 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	items := listOf(l["items"])
	if l["total"].(float64) != 3 {
		t.Fatalf("audit %v", l)
	}
	actions := []string{}
	for _, it := range items {
		actions = append(actions, mapOf(it)["action"].(string))
	}
	if strings.Join(actions, ",") != "web:member.role,POST /api-keys,PUT /settings/sla" {
		t.Fatalf("actions %v", actions)
	}
	key := mapOf(items[1])
	if mapOf(key["details"])["name"] != "CI deploy" || key["actor_role"] != "owner" || key["actor_kind"] != "user" {
		t.Fatalf("api key entry %v", key)
	}
	web := mapOf(items[0])
	if web["target_type"] != "member" || web["target_id"] != "u-2" || mapOf(web["details"])["role"] != "admin" {
		t.Fatalf("web entry %v", web)
	}
	if f := expect(t, do(t, "GET", "/api/v1/audit-log?action=sla", owner, nil), 200).body; f["total"].(float64) != 1 {
		t.Fatalf("filter %v", f)
	}
	if o := expect(t, do(t, "GET", "/api/v1/audit-log", token("tau2", "owner", false), nil), 200).body; o["total"].(float64) != 0 {
		t.Fatal("other tenant sees the audit log")
	}
}
