package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/alerts"
	"github.com/depguard/depguard/internal/notify"
	"github.com/depguard/depguard/internal/secretbox"
	"github.com/depguard/depguard/internal/teamcfg"
	"github.com/jackc/pgx/v5"
)

type notificationsResp struct {
	Settings        teamcfg.Notifications `json:"settings"`
	SlackConfigured bool                  `json:"slack_configured"`
	SlackHint       string                `json:"slack_hint"`
	JiraTokenSet    bool                  `json:"jira_token_set"`
	EmailConfigured bool                  `json:"email_configured"` // SMTP on this server
	SecretsEnabled  bool                  `json:"secrets_enabled"`  // DEPGUARD_SECRET_KEY set
}

func (s *Server) getNotifications(w http.ResponseWriter, r *http.Request) error {
	out := notificationsResp{EmailConfigured: notify.SMTPFromEnv().Configured()}
	_, keyErr := secretbox.Seal("x", "probe")
	out.SecretsEnabled = keyErr == nil
	err := s.tx(r, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(r.Context(), `SELECT notifications FROM tenant_settings`).Scan(&raw); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		out.Settings = teamcfg.ParseNotifications(raw)
		rows, err := tx.Query(r.Context(), `SELECT name, hint FROM tenant_secrets`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name, hint string
			if err := rows.Scan(&name, &hint); err != nil {
				return err
			}
			switch name {
			case alerts.SecretSlack:
				out.SlackConfigured, out.SlackHint = true, hint
			case alerts.SecretJira:
				out.JiraTokenSet = true
			}
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, out)
}

// putNotifications saves settings; secrets change only when their field is
// present ("" removes them) and are never returned.
func (s *Server) putNotifications(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Settings        teamcfg.Notifications `json:"settings"`
		SlackWebhookURL *string               `json:"slack_webhook_url"`
		JiraToken       *string               `json:"jira_token"`
	}
	body.Settings = teamcfg.DefaultNotifications()
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if err := body.Settings.Validate(); err != nil {
		return badRequest("%v", err)
	}
	if body.SlackWebhookURL != nil {
		*body.SlackWebhookURL = strings.TrimSpace(*body.SlackWebhookURL)
		if *body.SlackWebhookURL != "" && !notify.ValidSlackURL(*body.SlackWebhookURL) {
			return badRequest("Slack webhook URL must start with https://hooks.slack.com/")
		}
	}
	if body.JiraToken != nil && len(*body.JiraToken) > 500 {
		return badRequest("Jira API token is too long")
	}
	p := principal(r)
	b, _ := json.Marshal(body.Settings)
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE tenant_settings SET notifications=$1, updated_at=now()`, b)
		if err == nil && tag.RowsAffected() == 0 {
			return errf(http.StatusNotFound, "tenant not provisioned")
		}
		if err != nil {
			return err
		}
		save := func(name string, v *string, hint string) error {
			if v == nil {
				return nil
			}
			err := alerts.SaveSecret(r.Context(), tx, p.TenantID, name, *v, hint)
			if errors.Is(err, secretbox.ErrNoKey) {
				return errf(http.StatusServiceUnavailable, "this server has no DEPGUARD_SECRET_KEY, so secrets cannot be stored")
			}
			return err
		}
		if body.SlackWebhookURL != nil {
			hint := ""
			if u := *body.SlackWebhookURL; len(u) > 6 {
				hint = "…" + u[len(u)-6:]
			}
			if err := save(alerts.SecretSlack, body.SlackWebhookURL, hint); err != nil {
				return err
			}
		}
		return save(alerts.SecretJira, body.JiraToken, "")
	})
	if err != nil {
		return err
	}
	return s.getNotifications(w, r)
}

// testNotification sends a test message to one channel, on an admin's request.
func (s *Server) testNotification(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Channel string `json:"channel"`
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	var ch alerts.Channels
	p := principal(r)
	if err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		ch, err = alerts.Load(r.Context(), tx, p.TenantID)
		return err
	}); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	m := notify.Message{Title: "depguard test alert", Text: fmt.Sprintf("Sent by %s from Settings → Notifications. Alerts will look like this.", firstNonEmpty(p.Email, p.Name)),
		Lines: []string{"Malicious package: event-stream 3.3.6 (example)", "Critical: lodash 4.17.15 GHSA-35jh-r3h4-6jhm (example)"},
		Link:  strings.TrimRight(s.d.PublicURL, "/") + "/dashboard", LinkText: "Open depguard"}
	var err error
	switch body.Channel {
	case "slack":
		if ch.Slack == "" {
			return badRequest("add a Slack webhook URL first")
		}
		err = notify.Slack(ctx, ch.Slack, m)
	case "email":
		if len(ch.Cfg.EmailTo) == 0 {
			return badRequest("add at least one email recipient first")
		}
		err = notify.SMTPFromEnv().Email(ctx, ch.Cfg.EmailTo, m)
	case "jira":
		j, ok := ch.Jira()
		if !ok {
			return badRequest("fill in the Jira site, email, project and API token first")
		}
		err = j.Check(ctx)
	default:
		return badRequest("channel must be slack, email or jira")
	}
	if err != nil {
		return errf(http.StatusBadGateway, "%v", err)
	}
	return writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (s *Server) listJiraLinks(w http.ResponseWriter, r *http.Request) error {
	return s.listHandler("", `SELECT ref_kind, ref, issue_key, url, created_by, created_at FROM jira_links`,
		filterSpec{eq: map[string]string{"ref_kind": "t.ref_kind", "ref": "t.ref"}}, "t.created_at DESC", nil)(w, r)
}

// createJiraIssue opens a Jira issue for a vulnerability or a vulnerable
// package version, once per item.
func (s *Server) createJiraIssue(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		RefKind string `json:"ref_kind"` // vuln | package
		Ref     string `json:"ref"`      // advisory id | ecosystem/name@version
	}
	if err := decode(w, r, jsonLimit, &body); err != nil {
		return err
	}
	if (body.RefKind != "vuln" && body.RefKind != "package") || body.Ref == "" || len(body.Ref) > 300 {
		return badRequest("ref_kind must be vuln or package, with a ref")
	}
	p := principal(r)
	var ch alerts.Channels
	var m notify.Message
	var existing struct{ Key, URL string }
	err := s.tx(r, func(tx pgx.Tx) error {
		err := tx.QueryRow(r.Context(), `SELECT issue_key, url FROM jira_links WHERE ref_kind=$1 AND ref=$2`, body.RefKind, body.Ref).Scan(&existing.Key, &existing.URL)
		if err == nil || !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if ch, err = alerts.Load(r.Context(), tx, p.TenantID); err != nil {
			return err
		}
		m, err = jiraMessage(r.Context(), tx, body.RefKind, body.Ref, strings.TrimRight(s.d.PublicURL, "/"))
		return err
	})
	if err != nil {
		return err
	}
	if existing.Key != "" {
		return writeJSON(w, http.StatusOK, map[string]string{"issue_key": existing.Key, "url": existing.URL, "status": "exists"})
	}
	j, ok := ch.Jira()
	if !ok {
		return badRequest("Jira is not set up: add it in Settings → Notifications")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	key, url, err := j.Create(ctx, m, []string{"depguard", "security"})
	if err != nil {
		return errf(http.StatusBadGateway, "%v", err)
	}
	err = s.tx(r, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `INSERT INTO jira_links (tenant_id, ref_kind, ref, issue_key, url, created_by) VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT DO NOTHING`, p.TenantID, body.RefKind, body.Ref, key, url, firstNonEmpty(p.Email, p.Name, p.UserID))
		return err
	})
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusCreated, map[string]string{"issue_key": key, "url": url, "status": "created"})
}

// jiraMessage describes the vulnerability or package for the issue body.
func jiraMessage(ctx context.Context, tx pgx.Tx, kind, ref, base string) (notify.Message, error) {
	q := `SELECT DISTINCT c.name, c.version, cv.advisory_id, cv.risk, COALESCE(cv.fixed_in,''), p.name, COALESCE(a.summary,'')
FROM component_vulnerabilities cv JOIN components c ON c.id = cv.component_id
JOIN project_version_components pvc ON pvc.component_id = c.id JOIN project_versions pv ON pv.id = pvc.project_version_id
JOIN projects p ON p.id = pv.project_id LEFT JOIN advisory a ON a.id = cv.advisory_id `
	var args []any
	var m notify.Message
	if kind == "vuln" {
		q += `WHERE cv.advisory_id = $1`
		args = []any{ref}
		m.Link = base + "/vulnerabilities/" + ref
	} else {
		eco, rest, _ := strings.Cut(ref, "/")
		i := strings.LastIndex(rest, "@")
		if i <= 0 {
			return m, badRequest("package ref must be ecosystem/name@version")
		}
		q += `WHERE c.ecosystem = $1 AND c.name = $2 AND c.version = $3 AND cv.advisory_id NOT LIKE 'MAL-%'`
		args = []any{eco, rest[:i], rest[i+1:]}
		m.Link = base + "/fix-queue"
	}
	rows, err := tx.Query(ctx, q+` ORDER BY 6, 1`, args...)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	projects := map[string]bool{}
	fixed, summary, risk, name, version := "", "", "", "", ""
	for rows.Next() {
		var n, v, adv, rk, fx, proj, sum string
		if err := rows.Scan(&n, &v, &adv, &rk, &fx, &proj, &sum); err != nil {
			return m, err
		}
		name, version, summary, risk = n, v, sum, rk
		if fx != "" {
			fixed = fx
		}
		if !projects[proj] {
			projects[proj] = true
			m.Lines = append(m.Lines, fmt.Sprintf("%s uses %s %s (%s %s)", proj, n, v, adv, strings.ToLower(rk)))
		}
	}
	if err := rows.Err(); err != nil {
		return m, err
	}
	if len(projects) == 0 {
		return m, errNotFound
	}
	if kind == "vuln" {
		m.Title = fmt.Sprintf("[%s] Fix %s: %s", strings.ToLower(risk), ref, summary)
		m.Text = "This vulnerability affects the projects below."
	} else {
		m.Title = fmt.Sprintf("Upgrade %s from %s", name, version)
		if fixed != "" {
			m.Title += " to " + fixed
		}
		m.Text = "This package version has known vulnerabilities in the projects below."
	}
	return m, nil
}
