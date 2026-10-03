package ghapp_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/depguard/depguard/internal/engine/testpg"
	"github.com/depguard/depguard/internal/ghapp"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

const secret = "s3cret"

func sign(body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestWebhook(t *testing.T) {
	ctx := context.Background()
	pg := testpg.Start(t)
	_, err := pg.Owner.Exec(ctx, `
		INSERT INTO tenant_settings (tenant_id, domain, scan_draft_prs) VALUES ('t1', 't1.example', false);
		INSERT INTO gh_installations (id, account_login, account_type, account_id, tenant_id, status) VALUES
		  (1, 'pending-org', 'Organization', 101, NULL, 'pending'),
		  (2, 'acme', 'Organization', 202, 't1', 'linked');`)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := river.NewClient(riverpgxv5.New(pg.App), &river.Config{})
	if err != nil {
		t.Fatal(err)
	}
	h := ghapp.NewWebhookHandler(ghapp.Deps{Pool: pg.App, River: rc, Config: ghapp.Config{WebhookSecret: secret}})

	post := func(event, id, body, sig string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/github/webhook", bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-GitHub-Event", event)
		r.Header.Set("X-GitHub-Delivery", id)
		r.Header.Set("X-Hub-Signature-256", sig)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	send := func(event, id, body string) *httptest.ResponseRecorder {
		return post(event, id, body, sign([]byte(body)))
	}
	jobs := func(kind string) (n int) {
		if err := pg.Owner.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind=$1`, kind).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	status := func(id string) (s string) {
		if err := pg.Owner.QueryRow(ctx, `SELECT status FROM webhook_deliveries WHERE delivery_id=$1`, id).Scan(&s); err != nil && err != pgx.ErrNoRows {
			t.Fatal(err)
		}
		return s
	}
	pr := func(inst int, draft bool, sha string) string {
		d := "false"
		if draft {
			d = "true"
		}
		return `{"action":"opened","installation":{"id":` + itoa(inst) + `},"repository":{"id":9,"full_name":"acme/app","default_branch":"main"},
		  "pull_request":{"number":5,"draft":` + d + `,"head":{"sha":"` + sha + `","ref":"feat"},"base":{"sha":"b0","ref":"main"}}}`
	}

	t.Run("bad signature", func(t *testing.T) {
		body := pr(2, false, "h1")
		if w := post("pull_request", "d-bad", body, sign([]byte(body+"x"))); w.Code != http.StatusUnauthorized {
			t.Fatalf("code %d", w.Code)
		}
		if status("d-bad") != "" || jobs("scan_pull_request") != 0 {
			t.Fatal("bad signature must not be recorded or enqueued")
		}
	})

	t.Run("linked PR enqueues once; duplicate delivery ignored", func(t *testing.T) {
		if w := send("pull_request", "d1", pr(2, false, "h1")); w.Code != http.StatusAccepted {
			t.Fatalf("code %d %s", w.Code, w.Body)
		}
		if status("d1") != "enqueued" || jobs("scan_pull_request") != 1 {
			t.Fatalf("status %q jobs %d", status("d1"), jobs("scan_pull_request"))
		}
		if w := send("pull_request", "d1", pr(2, false, "h1")); w.Code != http.StatusOK {
			t.Fatalf("dup code %d", w.Code)
		}
		if jobs("scan_pull_request") != 1 {
			t.Fatal("duplicate delivery enqueued a job")
		}
	})

	t.Run("unlinked installation does nothing", func(t *testing.T) {
		send("pull_request", "d2", pr(1, false, "h2"))
		if status("d2") != "ignored" || jobs("scan_pull_request") != 1 {
			t.Fatalf("status %q jobs %d", status("d2"), jobs("scan_pull_request"))
		}
	})

	t.Run("draft skipped", func(t *testing.T) {
		send("pull_request", "d3", pr(2, true, "h3"))
		if status("d3") != "ignored" || jobs("scan_pull_request") != 1 {
			t.Fatalf("status %q jobs %d", status("d3"), jobs("scan_pull_request"))
		}
	})

	t.Run("push to default branch", func(t *testing.T) {
		body := `{"ref":"refs/heads/main","after":"c1","installation":{"id":2},"repository":{"id":9,"full_name":"acme/app","default_branch":"main"}}`
		send("push", "d4", body)
		other := `{"ref":"refs/heads/feat","after":"c2","installation":{"id":2},"repository":{"id":9,"full_name":"acme/app","default_branch":"main"}}`
		send("push", "d5", other)
		if jobs("scan_repository") != 1 || status("d5") != "ignored" {
			t.Fatalf("jobs %d", jobs("scan_repository"))
		}
	})

	t.Run("installation created inherits tenant of same account", func(t *testing.T) {
		body := `{"action":"created","installation":{"id":3,"account":{"login":"acme","type":"Organization","id":202}},
		  "repositories":[{"id":11,"full_name":"acme/lib","private":true}]}`
		send("installation", "d6", body)
		body = `{"action":"created","installation":{"id":4,"account":{"login":"new","type":"User","id":303}}}`
		send("installation", "d7", body)
		var st3, st4 string
		var tn3 *string
		pg.Owner.QueryRow(ctx, `SELECT status, tenant_id FROM gh_installations WHERE id=3`).Scan(&st3, &tn3)
		pg.Owner.QueryRow(ctx, `SELECT status FROM gh_installations WHERE id=4`).Scan(&st4)
		if st3 != "linked" || tn3 == nil || *tn3 != "t1" || st4 != "pending" {
			t.Fatalf("inst3 %s %v inst4 %s", st3, tn3, st4)
		}
		var repos int
		pg.Owner.QueryRow(ctx, `SELECT count(*) FROM gh_repositories WHERE installation_id=3`).Scan(&repos)
		if repos != 1 || jobs("sync_installation") != 2 {
			t.Fatalf("repos %d sync jobs %d", repos, jobs("sync_installation"))
		}
		send("installation", "d8", `{"action":"deleted","installation":{"id":3,"account":{"login":"acme","type":"Organization","id":202}}}`)
		pg.Owner.QueryRow(ctx, `SELECT status FROM gh_installations WHERE id=3`).Scan(&st3)
		if st3 != "deleted" || status("d8") != "processed" {
			t.Fatalf("status %s", st3)
		}
	})

	t.Run("check run rerequested", func(t *testing.T) {
		body := `{"action":"rerequested","installation":{"id":2},"repository":{"id":9,"full_name":"acme/app"},
		  "check_run":{"name":"depguard: Supply Chain Security","head_sha":"h9","pull_requests":[{"number":5,"head":{"sha":"h9","ref":"feat"},"base":{"sha":"b0","ref":"main"}}]}}`
		send("check_run", "d9", body)
		if status("d9") != "enqueued" || jobs("scan_pull_request") != 2 {
			t.Fatalf("status %q jobs %d", status("d9"), jobs("scan_pull_request"))
		}
	})
}

func itoa(i int) string { return string(rune('0' + i)) }

func TestInstallURL(t *testing.T) {
	if got := ghapp.InstallURL(ghapp.Config{Slug: "depguard-dev"}); got != "https://github.com/apps/depguard-dev/installations/new" {
		t.Fatal(got)
	}
}
