// Package alerts builds the team's alerts and weekly digest from the database
// and sends them through the configured channels (internal/notify). Every
// function runs inside the caller's tenant transaction.
package alerts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/notify"
	"github.com/depguard/depguard/internal/secretbox"
	"github.com/depguard/depguard/internal/teamcfg"
	"github.com/jackc/pgx/v5"
)

// Secret names in tenant_secrets.
const (
	SecretSlack = "slack_webhook"
	SecretJira  = "jira_token"
)

// Channels are a tenant's notification settings with decrypted secrets.
type Channels struct {
	Tenant    string
	Cfg       teamcfg.Notifications
	Slack     string // webhook URL; "" = off
	JiraToken string
}

// Load reads settings and secrets of the transaction's tenant.
func Load(ctx context.Context, tx pgx.Tx, tenant string) (Channels, error) {
	c := Channels{Tenant: tenant}
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT notifications FROM tenant_settings`).Scan(&raw); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return c, err
	}
	c.Cfg = teamcfg.ParseNotifications(raw)
	rows, err := tx.Query(ctx, `SELECT name, ciphertext FROM tenant_secrets`)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var box []byte
		if err := rows.Scan(&name, &box); err != nil {
			return c, err
		}
		v, err := secretbox.Open(box, tenant+"/"+name)
		if err != nil {
			continue // key rotated or missing: treat as not configured
		}
		switch name {
		case SecretSlack:
			c.Slack = v
		case SecretJira:
			c.JiraToken = v
		}
	}
	return c, rows.Err()
}

// SaveSecret stores (or with "" removes) an encrypted secret and a display hint.
func SaveSecret(ctx context.Context, tx pgx.Tx, tenant, name, value, hint string) error {
	if value == "" {
		_, err := tx.Exec(ctx, `DELETE FROM tenant_secrets WHERE name=$1`, name)
		return err
	}
	box, err := secretbox.Seal(value, tenant+"/"+name)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO tenant_secrets (tenant_id, name, ciphertext, hint) VALUES ($1,$2,$3,$4)
		ON CONFLICT (tenant_id, name) DO UPDATE SET ciphertext=EXCLUDED.ciphertext, hint=EXCLUDED.hint, updated_at=now()`, tenant, name, box, hint)
	return err
}

// Jira returns the Jira client, or false when Jira is not set up.
func (c Channels) Jira() (notify.Jira, bool) {
	j := notify.Jira{BaseURL: c.Cfg.Jira.BaseURL, Email: c.Cfg.Jira.Email, Token: c.JiraToken, ProjectKey: c.Cfg.Jira.ProjectKey, IssueType: c.Cfg.Jira.IssueType}
	return j, c.Cfg.JiraReady() && c.JiraToken != ""
}

// Any reports whether at least one alert channel is set up.
func (c Channels) Any(smtp notify.SMTP) bool {
	return c.Slack != "" || (len(c.Cfg.EmailTo) > 0 && smtp.Configured())
}

// Send delivers m to Slack and email; it fails only if every channel failed.
func (c Channels) Send(ctx context.Context, smtp notify.SMTP, m notify.Message) error {
	var errs []error
	sent := 0
	if c.Slack != "" {
		if err := notify.Slack(ctx, c.Slack, m); err != nil {
			errs = append(errs, fmt.Errorf("slack: %w", err))
		} else {
			sent++
		}
	}
	if len(c.Cfg.EmailTo) > 0 && smtp.Configured() {
		if err := smtp.Email(ctx, c.Cfg.EmailTo, m); err != nil {
			errs = append(errs, fmt.Errorf("email: %w", err))
		} else {
			sent++
		}
	}
	if sent == 0 && len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Item is one alert line with its dedupe key.
type Item struct {
	Key, Line string
}

// unsent drops items whose key was already delivered.
func unsent(ctx context.Context, tx pgx.Tx, items []Item) ([]Item, error) {
	if len(items) == 0 {
		return nil, nil
	}
	keys := make([]string, len(items))
	for i, it := range items {
		keys[i] = it.Key
	}
	rows, err := tx.Query(ctx, `SELECT key FROM notifications_sent WHERE key = ANY($1)`, keys)
	if err != nil {
		return nil, err
	}
	done, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, k := range done {
		seen[k] = true
	}
	var out []Item
	for _, it := range items {
		if !seen[it.Key] {
			seen[it.Key] = true
			out = append(out, it)
		}
	}
	return out, nil
}

// MarkSent records delivered keys.
func MarkSent(ctx context.Context, tx pgx.Tx, tenant string, items []Item) error {
	for _, it := range items {
		if _, err := tx.Exec(ctx, `INSERT INTO notifications_sent (tenant_id, key) VALUES ($1,$2) ON CONFLICT DO NOTHING`, tenant, it.Key); err != nil {
			return err
		}
	}
	return nil
}

// lines turns items into at most 10 message lines plus "and N more".
func lines(items []Item) []string {
	var out []string
	for i, it := range items {
		if i == 10 {
			out = append(out, fmt.Sprintf("…and %d more", len(items)-10))
			break
		}
		out = append(out, it.Line)
	}
	return out
}

const kevSQL = `EXISTS (SELECT 1 FROM cve_score cs WHERE cs.kev AND (cs.cve = cv.advisory_id OR cs.cve IN (SELECT alias FROM advisory_alias WHERE advisory_id = cv.advisory_id)))`

// ScanAlert lists new malware / critical / actively exploited findings of a
// full scan's project version that were not alerted before.
func ScanAlert(ctx context.Context, tx pgx.Tx, ch Channels, scanID, publicURL string) (notify.Message, []Item, error) {
	ev := ch.Cfg.Events
	var project string
	if err := tx.QueryRow(ctx, `SELECT p.name FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id=$1`, scanID).Scan(&project); err != nil {
		return notify.Message{}, nil, err
	}
	rows, err := tx.Query(ctx, `
WITH vul AS (SELECT c.id, c.name, c.version, cv.advisory_id, cv.risk
  FROM scans s JOIN project_version_components pvc ON pvc.project_version_id = s.project_version_id
  JOIN components c ON c.id = pvc.component_id JOIN component_vulnerabilities cv ON cv.component_id = c.id WHERE s.id = $1),
kev AS (SELECT v.advisory_id FROM (SELECT DISTINCT advisory_id FROM vul) v CROSS JOIN LATERAL (SELECT v.advisory_id AS advisory_id) cv WHERE `+kevSQL+`)
SELECT vul.id, vul.name, vul.version, vul.advisory_id, vul.risk, kev.advisory_id IS NOT NULL FROM vul LEFT JOIN kev ON kev.advisory_id = vul.advisory_id
UNION ALL
SELECT c.id, c.name, c.version, 'analysis', 'MALWARE', false
FROM scans s JOIN project_version_components pvc ON pvc.project_version_id = s.project_version_id
JOIN components c ON c.id = pvc.component_id
WHERE s.id = $1 AND (SELECT a.status FROM package_analyses a WHERE a.component_id = c.id ORDER BY a.created_at DESC LIMIT 1) = 'malicious'`, scanID)
	if err != nil {
		return notify.Message{}, nil, err
	}
	var mal, vul []Item
	for rows.Next() {
		var id, name, version, adv, risk string
		var kev bool
		if err := rows.Scan(&id, &name, &version, &adv, &risk, &kev); err != nil {
			rows.Close()
			return notify.Message{}, nil, err
		}
		pkg := name + " " + version
		switch {
		case strings.HasPrefix(adv, "MAL-") || adv == "analysis":
			if ev.Malware {
				mal = append(mal, Item{Key: "malware:" + id, Line: "Malicious package: " + pkg})
			}
		case risk == "CRITICAL" && ev.Critical, kev && ev.KEV:
			l := fmt.Sprintf("%s: %s %s", strings.ToLower(risk), pkg, adv)
			if kev {
				l += " (actively exploited)"
			}
			vul = append(vul, Item{Key: "vuln:" + id + ":" + adv, Line: strings.ToUpper(l[:1]) + l[1:]})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return notify.Message{}, nil, err
	}
	if mal, err = unsent(ctx, tx, mal); err != nil {
		return notify.Message{}, nil, err
	}
	if vul, err = unsent(ctx, tx, vul); err != nil {
		return notify.Message{}, nil, err
	}
	items := append(mal, vul...)
	if len(items) == 0 {
		return notify.Message{}, nil, nil
	}
	var parts []string
	if len(mal) > 0 {
		parts = append(parts, plural(len(mal), "malicious package", "malicious packages"))
	}
	if len(vul) > 0 {
		parts = append(parts, plural(len(vul), "critical or actively exploited vulnerability", "critical or actively exploited vulnerabilities"))
	}
	m := notify.Message{
		Title:    "depguard: " + strings.Join(parts, " and ") + " in " + project,
		Text:     "Found by the latest scan of " + project + ". Malicious packages should be removed before the next build.",
		Lines:    lines(items),
		Link:     strings.TrimRight(publicURL, "/") + "/scans/" + scanID,
		LinkText: "Open the scan report",
	}
	return m, items, nil
}

// PRAlert is the alert for a blocked pull request (once per head commit).
func PRAlert(ctx context.Context, tx pgx.Tx, ch Channels, prID, publicURL string) (notify.Message, []Item, error) {
	if !ch.Cfg.Events.PRBlocked {
		return notify.Message{}, nil, nil
	}
	var repo, title, author, level, head, state, projectID string
	var number, urgency int
	var reasons []struct {
		Text string `json:"text"`
	}
	err := tx.QueryRow(ctx, `SELECT pr.repo_full_name, pr.number, pr.title, pr.author_login, pr.urgency_level, pr.urgency, pr.head_sha, pr.state,
		COALESCE(p.id, ''), pr.reasons FROM pull_requests pr LEFT JOIN projects p ON p.gh_repo_id = pr.repo_id WHERE pr.id=$1`, prID).
		Scan(&repo, &number, &title, &author, &level, &urgency, &head, &state, &projectID, &reasons)
	if err != nil || state != "open" {
		return notify.Message{}, nil, err
	}
	items, err := unsent(ctx, tx, []Item{{Key: "pr:" + prID + ":" + head}})
	if err != nil || len(items) == 0 {
		return notify.Message{}, nil, err
	}
	m := notify.Message{
		Title:    fmt.Sprintf("depguard blocked PR #%d in %s (%s %d)", number, repo, level, urgency),
		Text:     fmt.Sprintf("%q by %s must be fixed before merging.", title, author),
		Link:     fmt.Sprintf("%s/pull-requests/%s/%d", strings.TrimRight(publicURL, "/"), projectID, number),
		LinkText: "Review the pull request",
	}
	for _, r := range reasons {
		m.Lines = append(m.Lines, r.Text)
	}
	return m, items, nil
}

// overdueSQL lists current vulnerabilities past their fix deadline (same defaults as teamcfg.DefaultSLA).
const overdueSQL = `
WITH sla AS (SELECT sla FROM tenant_settings),
cur AS (SELECT DISTINCT component_id FROM project_version_components)
SELECT c.id, c.name, c.version, cv.advisory_id, cv.risk, cv.first_seen,
  COALESCE(((SELECT sla FROM sla)->>lower(cv.risk))::int, CASE lower(cv.risk) WHEN 'critical' THEN 7 WHEN 'high' THEN 30 WHEN 'medium' THEN 90 ELSE 0 END) AS days
FROM component_vulnerabilities cv JOIN cur USING (component_id) JOIN components c ON c.id = cv.component_id
WHERE cv.advisory_id NOT LIKE 'MAL-%'`

// OverdueAlert lists vulnerabilities that passed their fix deadline since the last alert.
func OverdueAlert(ctx context.Context, tx pgx.Tx, ch Channels, publicURL string, now time.Time) (notify.Message, []Item, error) {
	if !ch.Cfg.Events.Overdue {
		return notify.Message{}, nil, nil
	}
	rows, err := tx.Query(ctx, overdueSQL)
	if err != nil {
		return notify.Message{}, nil, err
	}
	var items []Item
	for rows.Next() {
		var id, name, version, adv, risk string
		var first time.Time
		var days int
		if err := rows.Scan(&id, &name, &version, &adv, &risk, &first, &days); err != nil {
			rows.Close()
			return notify.Message{}, nil, err
		}
		if days > 0 && first.AddDate(0, 0, days).Before(now) {
			items = append(items, Item{Key: "overdue:" + id + ":" + adv, Line: fmt.Sprintf("%s %s: %s (%s, %d-day deadline)", name, version, adv, strings.ToLower(risk), days)})
		}
	}
	rows.Close()
	if items, err = unsent(ctx, tx, items); err != nil || len(items) == 0 {
		return notify.Message{}, nil, err
	}
	return notify.Message{
		Title:    "depguard: " + plural(len(items), "vulnerability", "vulnerabilities") + " passed the fix deadline",
		Text:     "These are still in your projects after the deadline your team set.",
		Lines:    lines(items),
		Link:     strings.TrimRight(publicURL, "/") + "/vulnerabilities?overdue=1",
		LinkText: "See overdue vulnerabilities",
	}, items, nil
}

// Digest is the weekly summary, sent once per ISO week on the chosen weekday.
func Digest(ctx context.Context, tx pgx.Tx, ch Channels, publicURL string, now time.Time) (notify.Message, []Item, error) {
	d := ch.Cfg.Digest
	if !d.Enabled || int(now.UTC().Weekday()) != d.Weekday {
		return notify.Message{}, nil, nil
	}
	y, w := now.UTC().ISOWeek()
	items, err := unsent(ctx, tx, []Item{{Key: fmt.Sprintf("digest:%d-W%02d", y, w)}})
	if err != nil || len(items) == 0 {
		return notify.Message{}, nil, err
	}
	var newVulns, fixed, malware, openPRs int
	err = tx.QueryRow(ctx, `
WITH cur AS (SELECT DISTINCT component_id FROM project_version_components)
SELECT
  (SELECT count(*) FROM component_vulnerabilities cv JOIN cur USING (component_id) WHERE cv.advisory_id NOT LIKE 'MAL-%' AND cv.first_seen >= now() - interval '7 days'),
  (SELECT count(*) FROM component_vulnerabilities WHERE seen_current AND resolved_at >= now() - interval '7 days'),
  (SELECT count(DISTINCT cv.component_id) FROM component_vulnerabilities cv JOIN cur USING (component_id) WHERE cv.advisory_id LIKE 'MAL-%'),
  (SELECT count(*) FROM pull_requests WHERE state = 'open' AND urgency_level IN ('critical','high'))`).Scan(&newVulns, &fixed, &malware, &openPRs)
	if err != nil {
		return notify.Message{}, nil, err
	}
	var overdue int
	rows, err := tx.Query(ctx, overdueSQL)
	if err != nil {
		return notify.Message{}, nil, err
	}
	for rows.Next() {
		var id, name, version, adv, risk string
		var first time.Time
		var days int
		if rows.Scan(&id, &name, &version, &adv, &risk, &first, &days) == nil && days > 0 && first.AddDate(0, 0, days).Before(now) {
			overdue++
		}
	}
	rows.Close()
	top, err := topFixes(ctx, tx)
	if err != nil {
		return notify.Message{}, nil, err
	}
	m := notify.Message{
		Title: fmt.Sprintf("depguard weekly: %s, %s fixed", plural(newVulns, "new vulnerability", "new vulnerabilities"), plural(fixed, "", "")),
		Text: fmt.Sprintf("%s past the fix deadline · %s · %s needing attention.",
			plural(overdue, "vulnerability", "vulnerabilities"), plural(malware, "malicious package", "malicious packages"), plural(openPRs, "open pull request", "open pull requests")),
		Link:     strings.TrimRight(publicURL, "/") + "/fix-queue",
		LinkText: "Open the fix queue",
	}
	if len(top) > 0 {
		m.Lines = append([]string{"Fix these first:"}, top...)
	}
	return m, items, nil
}

func topFixes(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `
SELECT c.name, c.version, count(DISTINCT cv.advisory_id), count(DISTINCT pv.project_id),
  sum(CASE cv.risk WHEN 'CRITICAL' THEN 10 WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 2 ELSE 1 END) AS w
FROM project_version_components pvc JOIN project_versions pv ON pv.id = pvc.project_version_id
JOIN components c ON c.id = pvc.component_id JOIN component_vulnerabilities cv ON cv.component_id = c.id
WHERE cv.advisory_id NOT LIKE 'MAL-%' AND COALESCE(cv.fixed_in, '') <> ''
GROUP BY c.name, c.version ORDER BY sum(CASE cv.risk WHEN 'CRITICAL' THEN 10 WHEN 'HIGH' THEN 5 WHEN 'MEDIUM' THEN 2 ELSE 1 END) * count(DISTINCT pv.project_id) DESC, c.name LIMIT 5`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, version string
		var advs, projects, w int
		if err := rows.Scan(&name, &version, &advs, &projects, &w); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s %s · %s in %s", name, version, plural(advs, "advisory", "advisories"), plural(projects, "project", "projects")))
	}
	return out, rows.Err()
}

func plural(n int, one, many string) string {
	if one == "" {
		return fmt.Sprint(n)
	}
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
