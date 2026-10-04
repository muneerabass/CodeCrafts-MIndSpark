package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var msg = Message{Title: "2 new critical vulnerabilities in acme/web", Text: "Fix <these> first.", Lines: []string{"lodash 4.17.15: GHSA-1"}, Link: "https://app/x"}

func TestValidators(t *testing.T) {
	for u, ok := range map[string]bool{
		"https://hooks.slack.com/services/T0/B0/abc": true, "http://hooks.slack.com/services/T0/B0/abc": false,
		"https://hooks.slack.com.evil.io/services/x": false, "https://169.254.169.254/latest": false,
	} {
		if ValidSlackURL(u) != ok {
			t.Errorf("slack %s", u)
		}
	}
	for u, ok := range map[string]bool{"https://acme.atlassian.net": true, "https://acme.atlassian.net/": true, "https://acme.atlassian.net.evil.io": false, "http://acme.atlassian.net": false} {
		if ValidJiraURL(u) != ok {
			t.Errorf("jira %s", u)
		}
	}
	if !ValidEmail("ada@acme.dev") || ValidEmail("ada@acme") || ValidEmail("Ada <ada@acme.dev>") {
		t.Error("email")
	}
}

func TestSlackAndJira(t *testing.T) {
	var got map[string]any
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		user, pass, _ := r.BasicAuth()
		auth, path = user+":"+pass, r.URL.Path
		if path == "/rest/api/3/issue" {
			w.Write([]byte(`{"key":"SEC-7"}`))
		}
	}))
	defer srv.Close()
	checkSlack, checkJira = func(string) bool { return true }, func(string) bool { return true }
	defer func() { checkSlack, checkJira = ValidSlackURL, ValidJiraURL }()

	if err := Slack(context.Background(), srv.URL, msg); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	if got["text"] != msg.Title || !strings.Contains(string(b), "Fix \\u0026lt;these\\u0026gt; first") || !strings.Contains(string(b), "https://app/x") {
		t.Fatalf("slack payload %s", b)
	}
	j := Jira{BaseURL: srv.URL, Email: "ada@acme.dev", Token: "tok", ProjectKey: "SEC"}
	key, url, err := j.Create(context.Background(), msg, []string{"depguard"})
	if err != nil || key != "SEC-7" || url != srv.URL+"/browse/SEC-7" || auth != "ada@acme.dev:tok" {
		t.Fatalf("%s %s %v %s", key, url, err, auth)
	}
	f := got["fields"].(map[string]any)
	if f["summary"] != msg.Title || f["issuetype"].(map[string]any)["name"] != "Task" {
		t.Fatalf("jira fields %v", f)
	}
	if err := Slack(context.Background(), srv.URL+"/fail", msg); err != nil {
		t.Fatal(err) // 200 from the fake even on other paths
	}
}

// fakeSMTP accepts one message and returns its DATA.
func fakeSMTP(t *testing.T) (string, <-chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		io.WriteString(c, "220 fake\r\n")
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				io.WriteString(c, "250 fake\r\n")
			case cmd == "DATA":
				io.WriteString(c, "354 go\r\n")
				for {
					l, _ := r.ReadString('\n')
					if l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				io.WriteString(c, "250 ok\r\n")
				out <- data.String()
			case cmd == "QUIT":
				io.WriteString(c, "221 bye\r\n")
				return
			default:
				io.WriteString(c, "250 ok\r\n")
			}
		}
	}()
	return ln.Addr().String(), out
}

func TestEmail(t *testing.T) {
	addr, out := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	c := SMTP{Host: host, Port: port, From: "depguard <alerts@acme.dev>"}
	if err := c.Email(context.Background(), []string{"sec@acme.dev"}, msg); err != nil {
		t.Fatal(err)
	}
	data := <-out
	for _, want := range []string{"To: sec@acme.dev", "multipart/alternative", "- lodash 4.17.15: GHSA-1", "Fix &lt;these&gt; first.", `href="https://app/x"`} {
		if !strings.Contains(data, want) {
			t.Fatalf("mail lacks %q:\n%s", want, data)
		}
	}
	if err := (SMTP{}).Email(context.Background(), []string{"a@b.co"}, msg); err == nil {
		t.Fatal("sent without SMTP_HOST")
	}
}
