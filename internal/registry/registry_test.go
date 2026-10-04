package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNPMAndPyPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/@acme%2Fsdk":
			w.Write([]byte(`{"time":{"created":"2020-01-01T00:00:00Z","1.0.0":"2024-01-01T00:00:00.000Z","1.0.1":"2026-10-03T10:00:00.000Z"},
			"versions":{
			 "1.0.0":{"_npmUser":{"name":"alice"},"scripts":{"test":"jest"},"dist":{"attestations":{"provenance":{"predicateType":"https://slsa.dev/provenance/v1"}}}},
			 "1.0.1":{"_npmUser":{"name":"mallory"},"scripts":{"postinstall":"node steal.js","test":"jest"},"dist":{}}}}`))
		case "/pypi/requests/json":
			w.Write([]byte(`{"releases":{"2.0":[{"upload_time_iso_8601":"2013-09-24T19:00:00.000000Z"},{"upload_time_iso_8601":"2013-09-24T18:00:00.000000Z"}],"9.9":[]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Client{NPMURL: srv.URL, PyPIURL: srv.URL}
	vs, err := c.NPM(context.Background(), "@acme/sdk")
	if err != nil || len(vs) != 2 {
		t.Fatalf("%v %v", vs, err)
	}
	cur, prev := Find(vs, "1.0.1")
	if cur.Publisher != "mallory" || cur.Provenance || cur.Scripts["postinstall"] != "node steal.js" || cur.Scripts["test"] != "" ||
		prev.Publisher != "alice" || !prev.Provenance || len(prev.Scripts) != 0 {
		t.Fatalf("cur %+v prev %+v", cur, prev)
	}
	if _, err := c.NPM(context.Background(), "nope"); err != ErrNotFound {
		t.Fatal(err)
	}
	py, err := c.PyPI(context.Background(), "requests")
	if err != nil || len(py) != 1 || py[0].Published.Hour() != 18 {
		t.Fatalf("%v %v", py, err)
	}
	if c, p := Find(py, "2.0"); c == nil || p != nil {
		t.Fatal("find first")
	}
}
