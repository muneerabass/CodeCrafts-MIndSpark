package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/auth"
	"github.com/depguard/depguard/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// handler returns an error that is mapped to a JSON error response.
type handler func(w http.ResponseWriter, r *http.Request) error

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func errf(code int, format string, a ...any) error {
	return &httpError{code, fmt.Sprintf(format, a...)}
}

func badRequest(format string, a ...any) error { return errf(http.StatusBadRequest, format, a...) }

var errNotFound = &httpError{http.StatusNotFound, "not found"}

func (s *Server) serve(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}
		var he *httpError
		var pe *pgconn.PgError
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &he):
			auth.JSONError(w, he.code, he.msg)
		case errors.Is(err, pgx.ErrNoRows):
			auth.JSONError(w, http.StatusNotFound, "not found")
		case errors.Is(err, db.ErrNoTenant):
			auth.JSONError(w, http.StatusForbidden, "tenant required")
		case errors.As(err, &mbe):
			auth.JSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
		case errors.As(err, &pe) && pe.Code == "23505":
			auth.JSONError(w, http.StatusConflict, "already exists")
		case errors.Is(err, context.Canceled):
			// client went away
		default:
			s.log.ErrorContext(r.Context(), "request failed", slog.String("path", r.URL.Path), slog.Any("err", err))
			auth.JSONError(w, http.StatusInternalServerError, "internal error")
		}
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(v)
}

// decode reads a JSON body of at most limit bytes into v.
func decode(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		return badRequest("invalid JSON body: %v", err)
	}
	return nil
}

func principal(r *http.Request) *auth.Principal { return auth.FromContext(r.Context()) }

// tx runs fn in the caller's tenant transaction.
func (s *Server) tx(r *http.Request, fn func(pgx.Tx) error) error {
	return db.WithTenantTx(r.Context(), s.d.Pool, principal(r).TenantID, fn)
}

// ------------------------------------------------------------ list helpers

type page struct{ limit, offset int }

func parsePage(r *http.Request) (page, error) {
	q := r.URL.Query()
	n, size := 1, 20
	if v := q.Get("page"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 {
			return page{}, badRequest("page must be a positive integer")
		}
		n = p
	}
	if v := q.Get("page_size"); v != "" {
		ps, err := strconv.Atoi(v)
		if err != nil || (ps != 10 && ps != 20 && ps != 50) {
			return page{}, badRequest("page_size must be 10, 20 or 50")
		}
		size = ps
	}
	return page{limit: size, offset: (n - 1) * size}, nil
}

// where accumulates SQL conditions; "?" in a condition becomes the next $n.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, vals ...any) {
	for _, v := range vals {
		w.args = append(w.args, v)
		cond = strings.Replace(cond, "?", "$"+strconv.Itoa(len(w.args)), 1)
	}
	w.conds = append(w.conds, cond)
}

func (w *where) sql() string {
	if len(w.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.conds, " AND ")
}

// filters applies common query-string filters to columns of the outer row t.
type filterSpec struct {
	eq      map[string]string // query param -> column (exact match)
	ilike   map[string]string // query param -> column (substring, case-insensitive)
	dateCol string            // from/to apply here
	vulns   bool              // has_vulns -> t.vulns > 0
	viols   bool              // has_violations -> t.violations > 0
}

func applyFilters(r *http.Request, f filterSpec, w *where) error {
	q := r.URL.Query()
	for p, col := range f.eq {
		if v := q.Get(p); v != "" {
			w.add(col+" = ?", v)
		}
	}
	for p, col := range f.ilike {
		if v := q.Get(p); v != "" {
			w.add(col+" ILIKE ?", "%"+escapeLike(v)+"%")
		}
	}
	if f.dateCol != "" {
		for p, op := range map[string]string{"from": ">=", "to": "<="} {
			if v := q.Get(p); v != "" {
				t, err := parseTime(v, p == "to")
				if err != nil {
					return badRequest("%s must be RFC3339 or YYYY-MM-DD", p)
				}
				w.add(f.dateCol+" "+op+" ?", t)
			}
		}
	}
	for p, col := range map[string]string{"has_vulns": "t.vulns", "has_violations": "t.violations"} {
		if (p == "has_vulns" && !f.vulns) || (p == "has_violations" && !f.viols) {
			continue
		}
		switch q.Get(p) {
		case "true":
			w.add(col + " > 0")
		case "false":
			w.add(col + " = 0")
		case "":
		default:
			return badRequest("%s must be true or false", p)
		}
	}
	return nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// parseTime accepts RFC3339 or a date; a date used as an upper bound means end of day.
func parseTime(v string, endOfDay bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return t, err
	}
	if endOfDay {
		t = t.Add(24*time.Hour - time.Nanosecond)
	}
	return t, nil
}

type listResp struct {
	Items []json.RawMessage `json:"items"`
	Total int64             `json:"total"`
}

// list pages through `inner` (a SELECT whose columns are the item fields),
// filtered by w on the outer alias t. hide removes helper columns from items.
// with is an optional "WITH ... " prefix.
func list(ctx context.Context, tx pgx.Tx, with, inner string, w *where, order string, p page, hide ...string) (*listResp, error) {
	from := " FROM (" + inner + ") t" + w.sql()
	resp := &listResp{Items: []json.RawMessage{}}
	if err := tx.QueryRow(ctx, with+"SELECT count(*)"+from, w.args...).Scan(&resp.Total); err != nil {
		return nil, err
	}
	sel := "to_jsonb(t)"
	args := w.args
	if len(hide) > 0 {
		args = append(append([]any{}, w.args...), hide)
		sel = fmt.Sprintf("to_jsonb(t) - $%d::text[]", len(args))
	}
	rows, err := tx.Query(ctx, fmt.Sprintf("%sSELECT %s%s ORDER BY %s LIMIT %d OFFSET %d", with, sel, from, order, p.limit, p.offset), args...)
	if err != nil {
		return nil, err
	}
	resp.Items, err = pgx.CollectRows(rows, pgx.RowTo[json.RawMessage])
	if resp.Items == nil {
		resp.Items = []json.RawMessage{}
	}
	return resp, err
}

// one returns the single JSON object produced by query (to_jsonb(...) column).
func one(ctx context.Context, tx pgx.Tx, query string, args ...any) (json.RawMessage, error) {
	var out json.RawMessage
	err := tx.QueryRow(ctx, query, args...).Scan(&out)
	return out, err
}

// sysTx runs fn without a tenant (global tables only, plus SECURITY DEFINER functions).
func (s *Server) sysTx(r *http.Request, fn func(pgx.Tx) error) error {
	return db.WithSystemTx(r.Context(), s.d.Pool, fn)
}

// listHandler is the common shape of tenant list endpoints.
func (s *Server) listHandler(with, inner string, f filterSpec, order string, extra func(*http.Request, *where) error, hide ...string) handler {
	return s.listIn(s.tx, with, inner, f, order, extra, hide...)
}

// sysList is listHandler over global tables (admin endpoints).
func (s *Server) sysList(inner string, f filterSpec, order string, extra func(*http.Request, *where) error, hide ...string) handler {
	return s.listIn(s.sysTx, "", inner, f, order, extra, hide...)
}

func (s *Server) listIn(txFn func(*http.Request, func(pgx.Tx) error) error, with, inner string, f filterSpec, order string,
	extra func(*http.Request, *where) error, hide ...string) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		p, err := parsePage(r)
		if err != nil {
			return err
		}
		wh := &where{}
		if err := applyFilters(r, f, wh); err != nil {
			return err
		}
		if extra != nil {
			if err := extra(r, wh); err != nil {
				return err
			}
		}
		var resp *listResp
		err = txFn(r, func(tx pgx.Tx) error {
			resp, err = list(r.Context(), tx, with, inner, wh, order, p, hide...)
			return err
		})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	}
}
