// Package notify delivers alerts and digests to Slack (incoming webhook),
// email (SMTP) and Jira Cloud (issues).
package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Message is one alert or digest, rendered for each channel.
type Message struct {
	Title    string   // "2 new critical vulnerabilities in acme/web"
	Text     string   // one-line summary
	Lines    []string // bullet points (plain text)
	Link     string   // dashboard URL
	LinkText string
}

// HTTP is the client used for Slack and Jira: short timeout, no redirects.
var HTTP = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

var slackURL = regexp.MustCompile(`^https://hooks\.slack\.com/(services|workflows|triggers)/[A-Za-z0-9/_-]+$`)

// ValidSlackURL accepts Slack incoming-webhook URLs only (no arbitrary hosts).
func ValidSlackURL(u string) bool { return slackURL.MatchString(u) }

// Destination checks, replaced in tests to point at local servers.
var checkSlack, checkJira = ValidSlackURL, ValidJiraURL

// Slack posts a message to an incoming webhook.
func Slack(ctx context.Context, webhook string, m Message) error {
	if !checkSlack(webhook) {
		return errors.New("not a Slack incoming webhook URL")
	}
	text := "*" + slackEscape(m.Title) + "*"
	if m.Text != "" {
		text += "\n" + slackEscape(m.Text)
	}
	blocks := []any{map[string]any{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": text}}}
	if len(m.Lines) > 0 {
		var b strings.Builder
		for _, l := range m.Lines {
			b.WriteString("• " + slackEscape(l) + "\n")
		}
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": trunc(b.String(), 2900)}})
	}
	if m.Link != "" {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{map[string]any{
			"type": "button", "text": map[string]string{"type": "plain_text", "text": firstNonEmpty(m.LinkText, "Open in depguard")}, "url": m.Link}}})
	}
	body, _ := json.Marshal(map[string]any{"text": m.Title, "blocks": blocks})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("slack: %s %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// SMTP is the outgoing mail server (SMTP_* environment, shared with the web app).
type SMTP struct{ Host, Port, User, Pass, From string }

func SMTPFromEnv() SMTP {
	c := SMTP{Host: os.Getenv("SMTP_HOST"), Port: os.Getenv("SMTP_PORT"), User: os.Getenv("SMTP_USER"), Pass: os.Getenv("SMTP_PASS"), From: os.Getenv("SMTP_FROM")}
	if c.Port == "" {
		c.Port = "587"
	}
	if c.From == "" {
		c.From = "depguard <no-reply@depguard.local>"
	}
	return c
}

func (c SMTP) Configured() bool { return strings.TrimSpace(c.Host) != "" }

// Email sends m to the recipients as one message (recipients see each other).
func (c SMTP) Email(ctx context.Context, to []string, m Message) error {
	if !c.Configured() {
		return errors.New("email is not configured on this server (SMTP_HOST)")
	}
	if len(to) == 0 {
		return errors.New("no recipients")
	}
	from, err := mailAddr(c.From)
	if err != nil {
		return err
	}
	msg := buildMail(c.From, to, m)
	addr := net.JoinHostPort(c.Host, c.Port)
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if c.Port == "465" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if c.Port != "465" {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err := cl.StartTLS(&tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return err
			}
		} else if c.User != "" && !isLocal(c.Host) {
			return errors.New("SMTP server does not offer STARTTLS; refusing to send credentials in clear text")
		}
	}
	if c.User != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.User, c.Pass, c.Host)); err != nil {
			return err
		}
	}
	if err := cl.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := cl.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func isLocal(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "mailpit"
}

var emailRe = regexp.MustCompile(`^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$`)

// ValidEmail is a plain address check (no display names).
func ValidEmail(s string) bool { return len(s) <= 254 && emailRe.MatchString(s) }

func mailAddr(from string) (string, error) {
	if i, j := strings.LastIndex(from, "<"), strings.LastIndex(from, ">"); i >= 0 && j > i {
		from = from[i+1 : j]
	}
	if !ValidEmail(from) {
		return "", fmt.Errorf("SMTP_FROM %q is not an email address", from)
	}
	return from, nil
}

func buildMail(from string, to []string, m Message) []byte {
	boundary := randHex(12)
	var b bytes.Buffer
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	hdr("From", from)
	hdr("To", strings.Join(to, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", m.Title))
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+randHex(16)+"@depguard>")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n--" + boundary + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(PlainText(m), "\n", "\r\n"))
	b.WriteString("\r\n--" + boundary + "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n")
	b.WriteString(HTML(m))
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return b.Bytes()
}

// PlainText renders m as the text part of an email.
func PlainText(m Message) string {
	var b strings.Builder
	b.WriteString(m.Title + "\n\n")
	if m.Text != "" {
		b.WriteString(m.Text + "\n\n")
	}
	for _, l := range m.Lines {
		b.WriteString("- " + l + "\n")
	}
	if m.Link != "" {
		b.WriteString("\n" + firstNonEmpty(m.LinkText, "Open in depguard") + ": " + m.Link + "\n")
	}
	return b.String()
}

// HTML renders m as the HTML part of an email (same look as the web app's invitation mail).
func HTML(m Message) string {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<div style="font-family:system-ui,sans-serif;max-width:560px;margin:auto;padding:24px">` +
		`<h2 style="color:#7c3aed;margin:0 0 16px">depguard</h2>` +
		`<h3 style="margin:0 0 8px">` + e(m.Title) + `</h3>`)
	if m.Text != "" {
		b.WriteString(`<p>` + e(m.Text) + `</p>`)
	}
	if len(m.Lines) > 0 {
		b.WriteString(`<ul style="padding-left:20px">`)
		for _, l := range m.Lines {
			b.WriteString(`<li style="margin:4px 0">` + e(l) + `</li>`)
		}
		b.WriteString(`</ul>`)
	}
	if m.Link != "" {
		b.WriteString(`<p><a href="` + e(m.Link) + `" style="display:inline-block;background:#7c3aed;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none">` +
			e(firstNonEmpty(m.LinkText, "Open in depguard")) + `</a></p>`)
	}
	b.WriteString(`<p style="color:#666;font-size:12px">You get this because your team turned on depguard alerts. Change them in Settings → Notifications.</p></div>`)
	return b.String()
}

// Jira is a Jira Cloud site and the project new issues go to.
type Jira struct {
	BaseURL, Email, Token, ProjectKey, IssueType string
}

var jiraURL = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]*\.atlassian\.net$`)

// ValidJiraURL accepts Jira Cloud sites only (https://<site>.atlassian.net).
func ValidJiraURL(u string) bool { return jiraURL.MatchString(strings.TrimRight(u, "/")) }

func (j Jira) do(ctx context.Context, method, path string, body any, out any) error {
	if !checkJira(j.BaseURL) {
		return errors.New("Jira site must be https://<your-site>.atlassian.net")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(j.BaseURL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(j.Email, j.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("jira: %s %s", resp.Status, trunc(strings.TrimSpace(string(b)), 300))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Check verifies the credentials and that the project exists.
func (j Jira) Check(ctx context.Context) error {
	return j.do(ctx, http.MethodGet, "/rest/api/3/project/"+url.PathEscape(j.ProjectKey), nil, nil)
}

// Create opens an issue and returns its key and browse URL.
func (j Jira) Create(ctx context.Context, m Message, labels []string) (string, string, error) {
	var content []any
	para := func(s string) map[string]any {
		return map[string]any{"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": s}}}
	}
	if m.Text != "" {
		content = append(content, para(m.Text))
	}
	if len(m.Lines) > 0 {
		var items []any
		for _, l := range m.Lines {
			items = append(items, map[string]any{"type": "listItem", "content": []any{para(l)}})
		}
		content = append(content, map[string]any{"type": "bulletList", "content": items})
	}
	if m.Link != "" {
		content = append(content, map[string]any{"type": "paragraph", "content": []any{map[string]any{"type": "text", "text": "View in depguard",
			"marks": []any{map[string]any{"type": "link", "attrs": map[string]string{"href": m.Link}}}}}})
	}
	body := map[string]any{"fields": map[string]any{
		"project":     map[string]string{"key": j.ProjectKey},
		"issuetype":   map[string]string{"name": firstNonEmpty(j.IssueType, "Task")},
		"summary":     trunc(m.Title, 250),
		"labels":      labels,
		"description": map[string]any{"type": "doc", "version": 1, "content": content},
	}}
	var out struct {
		Key string `json:"key"`
	}
	if err := j.do(ctx, http.MethodPost, "/rest/api/3/issue", body, &out); err != nil {
		return "", "", err
	}
	return out.Key, strings.TrimRight(j.BaseURL, "/") + "/browse/" + out.Key, nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
