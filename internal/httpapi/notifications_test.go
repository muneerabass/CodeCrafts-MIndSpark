package httpapi

import (
	"context"
	"strings"
	"testing"
)

func TestNotificationsSettings(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DEPGUARD_SECRET_KEY", strings.Repeat("ef", 32))
	t.Setenv("SMTP_HOST", "")
	_, err := tdb.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain) VALUES ('tn','n.test'), ('tn2','n2.test');
INSERT INTO jira_links (tenant_id, ref_kind, ref, issue_key, url) VALUES ('tn','vuln','GHSA-x','SEC-1','https://acme.atlassian.net/browse/SEC-1');`)
	if err != nil {
		t.Fatal(err)
	}
	member, owner, other := token("tn", "member", false), token("tn", "owner", false), token("tn2", "owner", false)

	g := expect(t, do(t, "GET", "/api/v1/settings/notifications", member, nil), 200).body
	if g["slack_configured"] != false || g["email_configured"] != false || g["secrets_enabled"] != true ||
		mapOf(mapOf(g["settings"])["events"])["malware"] != true {
		t.Fatalf("defaults %v", g)
	}
	settings := map[string]any{"email_to": []string{"sec@acme.dev"}, "events": map[string]bool{"malware": true, "critical": false},
		"digest": map[string]any{"enabled": true, "weekday": 5}, "jira": map[string]string{"base_url": "https://acme.atlassian.net/", "email": "ada@acme.dev", "project_key": "SEC", "issue_type": "Bug"}}
	expect(t, do(t, "PUT", "/api/v1/settings/notifications", member, map[string]any{"settings": settings}), 403)
	expect(t, do(t, "PUT", "/api/v1/settings/notifications", owner, map[string]any{"settings": settings, "slack_webhook_url": "https://evil.example/hook"}), 400)
	bad := map[string]any{"email_to": []string{"not-an-email"}}
	expect(t, do(t, "PUT", "/api/v1/settings/notifications", owner, map[string]any{"settings": bad}), 400)
	badJira := map[string]any{"jira": map[string]string{"base_url": "https://169.254.169.254"}}
	expect(t, do(t, "PUT", "/api/v1/settings/notifications", owner, map[string]any{"settings": badJira}), 400)

	p := expect(t, do(t, "PUT", "/api/v1/settings/notifications", owner, map[string]any{"settings": settings,
		"slack_webhook_url": "https://hooks.slack.com/services/T0/B0/secretpart", "jira_token": "jira-secret"}), 200).body
	s := mapOf(p["settings"])
	if p["slack_configured"] != true || p["slack_hint"] != "…etpart" || p["jira_token_set"] != true ||
		mapOf(s["jira"])["base_url"] != "https://acme.atlassian.net" || mapOf(s["digest"])["weekday"].(float64) != 5 {
		t.Fatalf("saved %v", p)
	}
	raw := do(t, "GET", "/api/v1/settings/notifications", owner, nil).raw
	if strings.Contains(raw, "secretpart") || strings.Contains(raw, "jira-secret") {
		t.Fatal("secret returned by the API")
	}
	var cipher string
	tdb.Owner.QueryRow(ctx, `SELECT encode(ciphertext,'escape') FROM tenant_secrets WHERE tenant_id='tn' AND name='slack_webhook'`).Scan(&cipher)
	if strings.Contains(cipher, "hooks.slack.com") {
		t.Fatal("secret stored in clear text")
	}
	// Saving without the secret fields keeps them; "" removes one.
	expect(t, do(t, "PUT", "/api/v1/settings/notifications", owner, map[string]any{"settings": settings}), 200)
	p = expect(t, do(t, "PUT", "/api/v1/settings/notifications", owner, map[string]any{"settings": settings, "slack_webhook_url": ""}), 200).body
	if p["slack_configured"] != false || p["jira_token_set"] != true {
		t.Fatalf("after removing slack %v", p)
	}
	if g := expect(t, do(t, "GET", "/api/v1/settings/notifications", other, nil), 200).body; g["jira_token_set"] != false {
		t.Fatal("other tenant sees secrets")
	}

	// Tests and Jira: refused when not set up; existing links are reused.
	expect(t, do(t, "POST", "/api/v1/settings/notifications/test", owner, map[string]string{"channel": "slack"}), 400)
	expect(t, do(t, "POST", "/api/v1/settings/notifications/test", owner, map[string]string{"channel": "fax"}), 400)
	if e := expect(t, do(t, "POST", "/api/v1/jira/issues", owner, map[string]string{"ref_kind": "vuln", "ref": "GHSA-x"}), 200).body; e["issue_key"] != "SEC-1" || e["status"] != "exists" {
		t.Fatalf("existing link %v", e)
	}
	expect(t, do(t, "POST", "/api/v1/jira/issues", owner, map[string]string{"ref_kind": "vuln", "ref": "GHSA-none"}), 404)
	expect(t, do(t, "POST", "/api/v1/jira/issues", member, map[string]string{"ref_kind": "vuln", "ref": "GHSA-x"}), 403)
	if l := expect(t, do(t, "GET", "/api/v1/jira/links", member, nil), 200).body; l["total"].(float64) != 1 {
		t.Fatalf("links %v", l)
	}
}
