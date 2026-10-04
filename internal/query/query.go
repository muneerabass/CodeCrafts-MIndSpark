// Package query runs tenant-scoped, read-only SQL for the Query page.
//
// Guards (defense in depth): the depguard_query role only has SELECT on q_*
// views (and RLS'd base tables); each run is a READ ONLY transaction with a 10 s
// statement_timeout and app.tenant set via SET LOCAL; the text must be one
// SELECT/WITH statement; results are capped at MaxRows. Migration 00002 revokes
// set_config from PUBLIC so a query cannot switch tenants mid-statement.
package query

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxRows is the row cap per query.
const MaxRows = 1000

// DefaultTimeout is the per-statement timeout.
const DefaultTimeout = 10 * time.Second

// Result is the JSON response of a query.
type Result struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Truncated bool     `json:"truncated"`
	ElapsedMS int64    `json:"elapsed_ms"`
}

// Executor runs queries on the depguard_query pool.
type Executor struct {
	Pool    *pgxpool.Pool
	Timeout time.Duration // zero means DefaultTimeout
	Role    string        // optional SET LOCAL ROLE (e.g. depguard_ai for AI-written queries)
}

// ErrInvalid wraps statement validation failures (HTTP 400).
var ErrInvalid = errors.New("invalid query")

var (
	lineComment  = regexp.MustCompile(`--[^\n]*`)
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	leadingWord  = regexp.MustCompile(`^(?i)(select|with)\b`)
	// Belt and braces for servers where set_config could not be revoked:
	// functions that set GUCs or execute SQL text, and unicode-escaped identifiers.
	denied = regexp.MustCompile(`(?i)(set_config|ts_stat|ts_rewrite|query_to_xml|cursor_to_xml|dblink|\bu&)`)
)

// Validate normalizes sql and checks that it is a single SELECT/WITH statement.
func Validate(sql string) (string, error) {
	s := blockComment.ReplaceAllString(sql, " ")
	s = lineComment.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
	if s == "" {
		return "", fmt.Errorf("%w: empty statement", ErrInvalid)
	}
	if len(s) > 20000 {
		return "", fmt.Errorf("%w: statement too long", ErrInvalid)
	}
	if strings.Contains(s, ";") {
		return "", fmt.Errorf("%w: only a single statement is allowed", ErrInvalid)
	}
	if !leadingWord.MatchString(s) {
		return "", fmt.Errorf("%w: only SELECT or WITH statements are allowed", ErrInvalid)
	}
	if m := denied.FindString(strings.ReplaceAll(s, `"`, "")); m != "" {
		return "", fmt.Errorf("%w: %q is not allowed", ErrInvalid, m)
	}
	return s, nil
}

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// Run executes sql for tenantID.
func (e *Executor) Run(ctx context.Context, tenantID, sql string) (*Result, error) {
	if tenantID == "" {
		return nil, errors.New("empty tenant")
	}
	stmt, err := Validate(sql)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	res := &Result{Columns: []string{}, Rows: [][]any{}}
	err = pgx.BeginTxFunc(ctx, e.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		timeout := e.Timeout
		if timeout == 0 {
			timeout = DefaultTimeout
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", timeout.Milliseconds())); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SET LOCAL app.tenant = "+quoteLiteral(tenantID)); err != nil {
			return err
		}
		if e.Role != "" {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{e.Role}.Sanitize()); err != nil {
				return err
			}
		}
		// Wrapping as a subquery forces a single SELECT and lets the server stop at the cap.
		rows, err := tx.Query(ctx, fmt.Sprintf("SELECT * FROM (%s\n) q LIMIT %d", stmt, MaxRows+1))
		if err != nil {
			return err
		}
		defer rows.Close()
		for _, f := range rows.FieldDescriptions() {
			res.Columns = append(res.Columns, f.Name)
		}
		for rows.Next() {
			if len(res.Rows) == MaxRows {
				res.Truncated = true
				break
			}
			vals, err := rows.Values()
			if err != nil {
				return err
			}
			for i, v := range vals {
				vals[i] = jsonSafe(v)
			}
			res.Rows = append(res.Rows, vals)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	res.ElapsedMS = time.Since(start).Milliseconds()
	return res, nil
}

// jsonSafe converts pgx values to types that marshal predictably.
func jsonSafe(v any) any {
	switch x := v.(type) {
	case nil, string, bool, int16, int32, int64, float32, map[string]any:
		return x
	case float64:
		return x
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case []byte:
		return base64.StdEncoding.EncodeToString(x)
	case [16]byte:
		return fmt.Sprintf("%x-%x-%x-%x-%x", x[0:4], x[4:6], x[6:8], x[8:10], x[10:16])
	case pgtype.Numeric:
		f, err := x.Float64Value()
		if err != nil || !f.Valid {
			return nil
		}
		return f.Float64
	case netip.Prefix:
		return x.String()
	case pgtype.Interval:
		return fmt.Sprintf("%d months %d days %d us", x.Months, x.Days, x.Microseconds)
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = jsonSafe(x[i])
		}
		return out
	case fmt.Stringer:
		return x.String()
	default:
		if _, err := json.Marshal(x); err == nil {
			return x
		}
		return fmt.Sprint(x)
	}
}

// Column of a queryable view.
type Column struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Table is a queryable view.
type Table struct {
	Name    string   `json:"name"`
	Columns []Column `json:"columns"`
}

// Schema lists q_* views visible to the query role.
func (e *Executor) Schema(ctx context.Context) ([]Table, error) {
	rows, err := e.Pool.Query(ctx, `SELECT table_name, column_name, data_type FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name LIKE 'q\_%' ORDER BY table_name, ordinal_position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tables := []Table{}
	for rows.Next() {
		var t, c, typ string
		if err := rows.Scan(&t, &c, &typ); err != nil {
			return nil, err
		}
		if len(tables) == 0 || tables[len(tables)-1].Name != t {
			tables = append(tables, Table{Name: t})
		}
		last := &tables[len(tables)-1]
		last.Columns = append(last.Columns, Column{c, typ})
	}
	return tables, rows.Err()
}
