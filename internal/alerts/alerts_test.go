package alerts

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/engine/testpg"
	"github.com/jackc/pgx/v5"
)

func TestAlerts(t *testing.T) {
	ctx := context.Background()
	pg := testpg.Start(t)
	t.Setenv("DEPGUARD_SECRET_KEY", strings.Repeat("cd", 32))
	_, err := pg.Owner.Exec(ctx, `
INSERT INTO tenant_settings (tenant_id, domain, notifications) VALUES ('t1','t1.example','{"email_to":["sec@acme.dev"],"digest":{"enabled":true,"weekday":1}}');
INSERT INTO projects (id, tenant_id, source, name, url, gh_repo_id) VALUES ('p1','t1','github','acme/web','',9);
INSERT INTO project_versions (id, tenant_id, project_id, name) VALUES ('v1','t1','p1','main');
INSERT INTO scans (id, tenant_id, project_id, project_version_id, trigger, status) VALUES ('s1','t1','p1','v1','push','success');
INSERT INTO components (id, tenant_id, ecosystem, name, version, purl) VALUES
  ('cm','t1','npm','evil','1.0.0','pkg:npm/evil@1.0.0'), ('cc','t1','npm','lodash','4.17.15','pkg:npm/lodash@4.17.15'),
  ('cl','t1','npm','debug','2.0.0','pkg:npm/debug@2.0.0');
INSERT INTO project_version_components (tenant_id, project_version_id, component_id, manifest_path) VALUES
  ('t1','v1','cm','package-lock.json'), ('t1','v1','cc','package-lock.json'), ('t1','v1','cl','package-lock.json');
INSERT INTO component_vulnerabilities (tenant_id, component_id, advisory_id, risk, fixed_in, first_seen) VALUES
  ('t1','cm','MAL-2026-1','CRITICAL',NULL, now()), ('t1','cc','GHSA-c','CRITICAL','4.17.21', now() - interval '9 days'),
  ('t1','cl','GHSA-l','LOW','2.6.9', now() - interval '400 days');
INSERT INTO pull_requests (id, tenant_id, repo_id, repo_full_name, number, title, author_login, state, head_sha, urgency, urgency_level, reasons)
  VALUES ('pr1','t1',9,'acme/web',4,'Add SDK','mallory','open','h1',100,'critical','[{"kind":"malware","text":"Adds malicious package evil"}]');`)
	if err != nil {
		t.Fatal(err)
	}
	in := func(fn func(tx pgx.Tx) error) {
		t.Helper()
		if err := db.WithTenantTx(ctx, pg.App, "t1", fn); err != nil {
			t.Fatal(err)
		}
	}
	var ch Channels
	in(func(tx pgx.Tx) error {
		if err := SaveSecret(ctx, tx, "t1", SecretSlack, "https://hooks.slack.com/services/T/B/c", "…/B/c"); err != nil {
			return err
		}
		var err error
		ch, err = Load(ctx, tx, "t1")
		return err
	})
	if ch.Slack != "https://hooks.slack.com/services/T/B/c" || len(ch.Cfg.EmailTo) != 1 || !ch.Cfg.Events.Malware {
		t.Fatalf("channels %+v", ch)
	}

	// Scan alert: malware + critical, once.
	in(func(tx pgx.Tx) error {
		m, items, err := ScanAlert(ctx, tx, ch, "s1", "https://app.example")
		if err != nil {
			return err
		}
		if len(items) != 2 || m.Title != "depguard: 1 malicious package and 1 critical or actively exploited vulnerability in acme/web" ||
			m.Lines[0] != "Malicious package: evil 1.0.0" || m.Lines[1] != "Critical: lodash 4.17.15 GHSA-c" || m.Link != "https://app.example/scans/s1" {
			t.Fatalf("scan alert %+v %v", m, items)
		}
		return MarkSent(ctx, tx, "t1", items)
	})
	in(func(tx pgx.Tx) error {
		_, items, err := ScanAlert(ctx, tx, ch, "s1", "https://app.example")
		if len(items) != 0 {
			t.Fatalf("repeated alert %v", items)
		}
		return err
	})

	// PR alert once per head commit.
	in(func(tx pgx.Tx) error {
		m, items, err := PRAlert(ctx, tx, ch, "pr1", "https://app.example")
		if err != nil || len(items) != 1 || !strings.Contains(m.Title, "PR #4 in acme/web") || m.Lines[0] != "Adds malicious package evil" || m.Link != "https://app.example/pull-requests/p1/4" {
			t.Fatalf("pr alert %+v %v %v", m, items, err)
		}
		return nil
	})

	// Overdue: the critical (9 days > 7) only; low has no deadline.
	now := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC) // a Monday
	in(func(tx pgx.Tx) error {
		m, items, err := OverdueAlert(ctx, tx, ch, "https://app.example", time.Now())
		if err != nil || len(items) != 1 || !strings.HasPrefix(m.Lines[0], "lodash 4.17.15: GHSA-c (critical, 7-day deadline)") {
			t.Fatalf("overdue %+v %v %v", m, items, err)
		}
		// Digest only on the chosen weekday, once a week.
		if _, items, _ := Digest(ctx, tx, ch, "https://app.example", now.Add(24*time.Hour)); len(items) != 0 {
			t.Fatal("digest on the wrong day")
		}
		m, items, err = Digest(ctx, tx, ch, "https://app.example", now)
		if err != nil || len(items) != 1 || items[0].Key != "digest:2026-W41" || !strings.Contains(m.Text, "1 malicious package") ||
			len(m.Lines) < 2 || !strings.HasPrefix(m.Lines[1], "lodash 4.17.15") {
			t.Fatalf("digest %+v %v %v", m, items, err)
		}
		return MarkSent(ctx, tx, "t1", items)
	})
	in(func(tx pgx.Tx) error {
		if _, items, _ := Digest(ctx, tx, ch, "https://app.example", now); len(items) != 0 {
			t.Fatal("digest sent twice in a week")
		}
		return nil
	})
}
