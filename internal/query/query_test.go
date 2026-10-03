package query

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/depguard/depguard/internal/httpapi/pgtest"
)

func TestValidate(t *testing.T) {
	good := []string{
		"select 1",
		"  SELECT * FROM q_projects;  ",
		"-- comment\nWITH x AS (SELECT 1) SELECT * FROM x",
		"/* hi; there */ select 1 -- trailing; comment",
	}
	for _, s := range good {
		if _, err := Validate(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := []string{
		"", ";", "delete from projects", "select 1; select 2", "update q_projects set name='x'",
		"select set_config('app.tenant','b',true)", `select "set_config"('app.tenant','b',true)`,
		"select ts_stat('select 1')", "SET app.tenant = 'b'", `select U&"\0073et_config"('a','b',true)`,
		"insert into projects values (1)", "explain analyze delete from projects",
	}
	for _, s := range bad {
		if _, err := Validate(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: expected ErrInvalid, got %v", s, err)
		}
	}
}

var tdb *pgtest.DB

func TestMain(m *testing.M) {
	if os.Getenv("SKIP_DB_TESTS") == "" {
		var err error
		if tdb, err = pgtest.Start(context.Background()); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	if tdb != nil {
		tdb.Close()
	}
	os.Exit(code)
}

func TestExecutor(t *testing.T) {
	if tdb == nil {
		t.Skip("no db")
	}
	ctx := context.Background()
	_, err := tdb.Owner.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, source, name) VALUES ('pa','ta','cli','alpha'), ('pb','tb','cli','beta');
		INSERT INTO advisory (id, source, modified, raw, risk) VALUES ('GHSA-1','npm', now(), '{}', 'HIGH');
		INSERT INTO projects (id, tenant_id, source, name) SELECT 'g'||i, 'ta', 'cli', 'gen'||i FROM generate_series(1,1100) i;`)
	if err != nil {
		t.Fatal(err)
	}
	e := &Executor{Pool: tdb.Query, Timeout: time.Second}

	res, err := e.Run(ctx, "ta", "select name, created_at from q_projects where name in ('alpha','beta')")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0][0] != "alpha" || res.Columns[1] != "created_at" {
		t.Fatalf("tenant isolation via view: %+v", res)
	}
	if _, ok := res.Rows[0][1].(string); !ok {
		t.Fatalf("timestamp not json-safe: %T", res.Rows[0][1])
	}
	// Base tables still enforce RLS for the query role.
	res, err = e.Run(ctx, "tb", "select name from projects")
	if err != nil || len(res.Rows) != 1 || res.Rows[0][0] != "beta" {
		t.Fatalf("base table RLS: %v %+v", err, res)
	}
	// Global advisory view is readable.
	if res, err = e.Run(ctx, "tb", "select id from q_vulnerabilities"); err != nil || len(res.Rows) != 1 {
		t.Fatalf("q_vulnerabilities: %v %+v", err, res)
	}
	// Row cap.
	res, err = e.Run(ctx, "ta", "select id from q_projects")
	if err != nil || len(res.Rows) != MaxRows || !res.Truncated {
		t.Fatalf("cap: %v len=%d truncated=%v", err, len(res.Rows), res.Truncated)
	}
	// Writes fail (read-only tx and no privileges), even through a CTE.
	for _, q := range []string{
		"with d as (delete from projects returning 1) select * from d",
		"with d as (insert into saved_queries (id,tenant_id,name,sql,created_by) values ('x','ta','n','s','u') returning 1) select * from d",
	} {
		if _, err := e.Run(ctx, "ta", q); err == nil {
			t.Errorf("write allowed: %s", q)
		}
	}
	// No access to tables outside the views' grants.
	if _, err := e.Run(ctx, "ta", "select * from api_keys"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("api_keys readable: %v", err)
	}
	// set_config is revoked at the database level too (bypassing Validate).
	_, err = tdb.Query.Exec(ctx, "select ts_stat('select to_tsvector(set_config(''app.tenant'',''tb'',true))')")
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("set_config callable by query role: %v", err)
	}
	// Timeout.
	start := time.Now()
	if _, err := e.Run(ctx, "ta", "select pg_sleep(5)"); err == nil || time.Since(start) > 4*time.Second {
		t.Errorf("timeout not enforced: %v after %s", err, time.Since(start))
	}
	// Schema lists q_ views only.
	tables, err := e.Schema(ctx)
	if err != nil || len(tables) < 14 {
		t.Fatalf("schema: %v %d", err, len(tables))
	}
	for _, tb := range tables {
		if !strings.HasPrefix(tb.Name, "q_") || len(tb.Columns) == 0 {
			t.Errorf("unexpected table %+v", tb)
		}
	}
}
