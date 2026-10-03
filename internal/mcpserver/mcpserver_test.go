package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/httpapi/pgtest"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestTools(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") != "" {
		t.Skip("no db")
	}
	ctx := context.Background()
	tdb, err := pgtest.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tdb.Close()
	err = feeds.New(tdb.App, feeds.Options{}).Ingest(ctx, "test", [][]byte{
		[]byte(`{"id":"GHSA-high","summary":"ReDoS in lodash","aliases":["CVE-2021-23337"],"modified":"2024-01-01T00:00:00Z",
		  "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
		  "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`),
		[]byte(`{"id":"MAL-2024-9","summary":"Malicious code in evil-pkg","modified":"2024-01-01T00:00:00Z",
		  "affected":[{"package":{"ecosystem":"npm","name":"evil-pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tdb.Owner.Exec(ctx, `
		INSERT INTO components (id, tenant_id, ecosystem, name, version, purl) VALUES ('c1','ta','npm','sus','1.0.0','pkg:npm/sus@1.0.0');
		INSERT INTO package_analyses (id, tenant_id, component_id, status, source) VALUES ('a1','ta','c1','suspicious','guarddog')`)
	if err != nil {
		t.Fatal(err)
	}
	// Stand-in for deps.dev and Scorecard.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/systems/npm/packages/lodash/versions/4.17.20":
			w.Write([]byte(`{"licenses":["MIT"],"relatedProjects":[{"projectKey":{"id":"github.com/lodash/lodash"},"relationType":"SOURCE_REPO"}]}`))
		case "/v3/projects/github.com/lodash/lodash":
			w.Write([]byte(`{"starsCount":100,"forksCount":10}`))
		case "/projects/github.com/lodash/lodash":
			w.Write([]byte(`{"score":6.8,"checks":[{"name":"Maintained","score":6}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	enr := enrich.New(tdb.App, enrich.Options{DepsDevURL: api.URL, ScorecardURL: api.URL})
	key, err := auth.CreateKey(ctx, tdb.App, "ta", "u", "mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", auth.APIKeyMiddleware(tdb.App, 100, 100, Handler(tdb.App, enr)))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Unauthenticated requests are rejected before MCP.
	res, _ := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if res.StatusCode != 401 {
		t.Fatalf("no key: %d", res.StatusCode)
	}

	c, err := client.NewStreamableHttpClient(srv.URL+"/mcp", transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + key.Key}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	init.Params.ClientInfo = mcp.Implementation{Name: "test", Version: "1"}
	if _, err := c.Initialize(ctx, init); err != nil {
		t.Fatal(err)
	}
	lt, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil || len(lt.Tools) != 4 {
		t.Fatalf("tools: %v %v", err, lt)
	}
	call := func(tool, eco, name, ver string) map[string]any {
		t.Helper()
		req := mcp.CallToolRequest{}
		req.Params.Name = tool
		req.Params.Arguments = map[string]any{"ecosystem": eco, "name": name, "version": ver}
		r, err := c.CallTool(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if r.IsError {
			t.Fatalf("%s: tool error %v", tool, r.Content)
		}
		var out map[string]any
		b, _ := json.Marshal(r.StructuredContent)
		json.Unmarshal(b, &out)
		return out
	}
	v := call("get_package_vulnerabilities", "npm", "lodash", "4.17.20")
	if v["count"].(float64) != 1 || !strings.Contains(mustJSON(v), "GHSA-high") || !strings.Contains(mustJSON(v), `"risk":"HIGH"`) {
		t.Fatalf("vulns: %v", v)
	}
	if v := call("get_package_vulnerabilities", "NPM", "lodash", "4.17.21"); v["count"].(float64) != 0 {
		t.Fatalf("fixed version: %v", v)
	}
	if m := call("get_malware_verdict", "npm", "evil-pkg", "2.0.0"); m["verdict"] != "malicious" {
		t.Fatalf("malware: %v", m)
	}
	if m := call("get_malware_verdict", "npm", "sus", "1.0.0"); m["verdict"] != "suspicious" {
		t.Fatalf("suspicious: %v", m)
	}
	if m := call("get_malware_verdict", "npm", "lodash", "4.17.20"); m["verdict"] != "no_known_malware" {
		t.Fatalf("clean: %v", m)
	}
	if l := call("get_license_info", "npm", "lodash", "4.17.20"); mustJSON(l["licenses"]) != `["MIT"]` {
		t.Fatalf("license: %v", l)
	}
	sc := call("get_package_scorecard", "npm", "lodash", "4.17.20")
	if !strings.Contains(mustJSON(sc), `"score":6.8`) || !strings.Contains(mustJSON(sc), "github.com/lodash/lodash") {
		t.Fatalf("scorecard: %v", sc)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
