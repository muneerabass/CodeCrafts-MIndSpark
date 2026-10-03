// Package feeds mirrors open vulnerability data into the global feed tables:
// OSV advisories (advisory, advisory_alias, affected), CISA KEV and FIRST EPSS
// (cve_score). Every source records progress in sync_state, so runs are
// idempotent and resume from the stored cursor.
//
// Entry points: New(pool, Options).SyncAll / SyncOSV / SyncKEV / SyncEPSS for
// direct use (cmd/depguard-feeds), PeriodicJobs + AddWorkers for River, and
// Status for the admin ops page.
package feeds

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// DefaultEcosystems are the OSV bucket directories synced by default.
var DefaultEcosystems = []string{"npm", "PyPI", "Go", "Maven", "crates.io", "RubyGems", "Packagist", "GitHub Actions"}

// Options configures a Syncer. Zero values use the public endpoints.
type Options struct {
	OSVBaseURL string   // default https://osv-vulnerabilities.storage.googleapis.com
	Ecosystems []string // default DefaultEcosystems
	KEVURL     string   // default CISA known_exploited_vulnerabilities.json
	EPSSURLs   []string // tried in order; default empiricalsecurity.com then cyentia.com
	// MaxIncremental: more changed records than this since the cursor
	// triggers an all.zip re-bootstrap instead of per-record fetches.
	MaxIncremental int // default 5000
	HTTPClient     *http.Client
	Logger         *slog.Logger
}

// Syncer runs feed syncs against a pool (depguard_app role is enough).
type Syncer struct {
	pool *pgxpool.Pool
	o    Options
}

// New returns a Syncer with defaults filled in.
func New(pool *pgxpool.Pool, o Options) *Syncer {
	if o.OSVBaseURL == "" {
		o.OSVBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
	}
	o.OSVBaseURL = strings.TrimRight(o.OSVBaseURL, "/")
	if len(o.Ecosystems) == 0 {
		o.Ecosystems = DefaultEcosystems
	}
	if o.KEVURL == "" {
		o.KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}
	if len(o.EPSSURLs) == 0 {
		o.EPSSURLs = []string{
			"https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
			"https://epss.cyentia.com/epss_scores-current.csv.gz",
		}
	}
	if o.MaxIncremental == 0 {
		o.MaxIncremental = 5000
	}
	if o.HTTPClient == nil {
		// No overall timeout: all.zip downloads are large; callers bound ctx.
		o.HTTPClient = &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ResponseHeaderTimeout: 60 * time.Second,
		}}
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Syncer{pool: pool, o: o}
}

// run loads sync_state for source, calls fn(cursor, etag) and records the outcome.
func (s *Syncer) run(ctx context.Context, source string, fn func(cursor, etag string) (string, string, error)) error {
	var cursor, etag *string
	err := s.pool.QueryRow(ctx, `SELECT cursor, etag FROM sync_state WHERE source = $1`, source).Scan(&cursor, &etag)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	nc, ne, runErr := fn(deref(cursor), deref(etag))
	if runErr != nil {
		_, err = s.pool.Exec(ctx, `INSERT INTO sync_state (source, last_error, updated_at) VALUES ($1, $2, now())
			ON CONFLICT (source) DO UPDATE SET last_error = EXCLUDED.last_error, updated_at = now()`, source, runErr.Error())
		return errors.Join(fmt.Errorf("%s: %w", source, runErr), err)
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO sync_state (source, cursor, etag, last_ok, last_error, updated_at)
		VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), now(), NULL, now())
		ON CONFLICT (source) DO UPDATE SET cursor = EXCLUDED.cursor, etag = EXCLUDED.etag,
		  last_ok = now(), last_error = NULL, updated_at = now()`, source, nc, ne)
	return err
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// SyncAllOSV syncs the given OSV ecosystems (default: Options.Ecosystems)
// sequentially, continuing past failures.
func (s *Syncer) SyncAllOSV(ctx context.Context, ecosystems []string) error {
	if len(ecosystems) == 0 {
		ecosystems = s.o.Ecosystems
	}
	var errs []error
	for _, eco := range ecosystems {
		if err := s.SyncOSV(ctx, eco); err != nil {
			s.o.Logger.Error("osv sync failed", "ecosystem", eco, "err", err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SyncAll runs OSV, KEV and EPSS once.
func (s *Syncer) SyncAll(ctx context.Context) error {
	return errors.Join(s.SyncAllOSV(ctx, nil), s.SyncKEV(ctx), s.SyncEPSS(ctx))
}

// SyncKEV mirrors the CISA KEV catalog into cve_score (conditional on ETag).
func (s *Syncer) SyncKEV(ctx context.Context) error {
	return s.run(ctx, "kev", func(cursor, etag string) (string, string, error) {
		hdr := map[string]string{}
		if etag != "" {
			hdr["If-None-Match"] = etag
		}
		resp, err := s.get(ctx, s.o.KEVURL, hdr)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotModified {
			return cursor, etag, nil
		}
		var feed struct {
			CatalogVersion  string `json:"catalogVersion"`
			Vulnerabilities []struct {
				CveID     string `json:"cveID"`
				DateAdded string `json:"dateAdded"`
				Ransom    string `json:"knownRansomwareCampaignUse"`
			} `json:"vulnerabilities"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
			return "", "", fmt.Errorf("decode kev: %w", err)
		}
		if len(feed.Vulnerabilities) == 0 {
			return "", "", errors.New("kev feed has no vulnerabilities")
		}
		var cves, added []string
		var ransom []bool
		for _, v := range feed.Vulnerabilities {
			cves, added = append(cves, v.CveID), append(added, v.DateAdded)
			ransom = append(ransom, strings.EqualFold(v.Ransom, "Known"))
		}
		b := &pgx.Batch{}
		b.Queue(`INSERT INTO cve_score (cve, kev, kev_added, ransomware)
			SELECT DISTINCT ON (c) c, true, NULLIF(d, '')::date, r FROM unnest($1::text[], $2::text[], $3::bool[]) AS t(c, d, r)
			ON CONFLICT (cve) DO UPDATE SET kev = true, kev_added = EXCLUDED.kev_added, ransomware = EXCLUDED.ransomware`,
			cves, added, ransom)
		b.Queue(`UPDATE cve_score SET kev = false, kev_added = NULL, ransomware = false WHERE kev AND NOT (cve = ANY($1))`, cves)
		err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return tx.SendBatch(ctx, b).Close() })
		if err != nil {
			return "", "", err
		}
		s.o.Logger.Info("kev: synced", "cves", len(cves), "catalog", feed.CatalogVersion)
		return feed.CatalogVersion, resp.Header.Get("ETag"), nil
	})
}

// SyncEPSS mirrors the daily EPSS scores into cve_score. Cursor = score date.
func (s *Syncer) SyncEPSS(ctx context.Context) error {
	return s.run(ctx, "epss", func(cursor, etag string) (string, string, error) {
		hdr := map[string]string{}
		if etag != "" {
			hdr["If-None-Match"] = etag
		}
		var resp *http.Response
		var errs []error
		for _, u := range s.o.EPSSURLs {
			r, err := s.get(ctx, u, hdr)
			if err == nil {
				resp = r
				break
			}
			errs = append(errs, err)
		}
		if resp == nil {
			return "", "", errors.Join(errs...)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotModified {
			return cursor, etag, nil
		}
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return "", "", fmt.Errorf("epss gzip: %w", err)
		}
		br := bufio.NewReader(gz)
		// "#model_version:v2025.03.14,score_date:2025-03-14T00:00:00+0000"
		first, err := br.ReadString('\n')
		if err != nil {
			return "", "", fmt.Errorf("epss header: %w", err)
		}
		_, date, _ := strings.Cut(first, "score_date:")
		if len(date) < 10 {
			return "", "", fmt.Errorf("epss: no score_date in %q", strings.TrimSpace(first))
		}
		date = date[:10]
		newETag := resp.Header.Get("ETag")
		if date == cursor {
			return cursor, newETag, nil
		}
		day, err := time.Parse(time.DateOnly, date)
		if err != nil {
			return "", "", fmt.Errorf("epss score_date: %w", err)
		}
		cr := csv.NewReader(br)
		cr.ReuseRecord = true
		if _, err := cr.Read(); err != nil { // header cve,epss,percentile
			return "", "", fmt.Errorf("epss csv header: %w", err)
		}
		var n int64
		err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `CREATE TEMP TABLE epss_stage (cve text, epss real, percentile real) ON COMMIT DROP`); err != nil {
				return err
			}
			_, err := tx.CopyFrom(ctx, pgx.Identifier{"epss_stage"}, []string{"cve", "epss", "percentile"},
				pgx.CopyFromFunc(func() ([]any, error) {
					for {
						rec, err := cr.Read()
						if errors.Is(err, io.EOF) {
							return nil, nil
						}
						if err != nil {
							return nil, err
						}
						if len(rec) < 3 {
							continue
						}
						e, err1 := strconv.ParseFloat(rec[1], 32)
						p, err2 := strconv.ParseFloat(rec[2], 32)
						if err1 != nil || err2 != nil {
							continue
						}
						return []any{rec[0], float32(e), float32(p)}, nil
					}
				}))
			if err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO cve_score (cve, epss, percentile, epss_date)
				SELECT DISTINCT ON (cve) cve, epss, percentile, $1 FROM epss_stage
				ON CONFLICT (cve) DO UPDATE SET epss = EXCLUDED.epss, percentile = EXCLUDED.percentile, epss_date = EXCLUDED.epss_date`, day)
			n = tag.RowsAffected()
			return err
		})
		if err != nil {
			return "", "", err
		}
		s.o.Logger.Info("epss: synced", "rows", n, "date", date)
		return date, newETag, nil
	})
}

// SourceStatus is one sync_state row, for the admin ops page.
type SourceStatus struct {
	Source    string     `json:"source"`
	LastOK    *time.Time `json:"last_ok"`
	LastError *string    `json:"last_error"`
	Cursor    *string    `json:"cursor"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Status returns every feed source's sync state, ordered by source.
func Status(ctx context.Context, pool *pgxpool.Pool) ([]SourceStatus, error) {
	rows, err := pool.Query(ctx, `SELECT source, last_ok, last_error, cursor, updated_at FROM sync_state ORDER BY source`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SourceStatus, error) {
		var st SourceStatus
		err := r.Scan(&st.Source, &st.LastOK, &st.LastError, &st.Cursor, &st.UpdatedAt)
		return st, err
	})
}

// ---------------------------------------------------------------- River

// OSVArgs syncs OSV ecosystems (empty = all defaults).
type OSVArgs struct {
	Ecosystems []string `json:"ecosystems,omitempty"`
}

func (OSVArgs) Kind() string { return "feeds_osv" }

// KEVArgs syncs the CISA KEV catalog.
type KEVArgs struct{}

func (KEVArgs) Kind() string { return "feeds_kev" }

// EPSSArgs syncs EPSS scores.
type EPSSArgs struct{}

func (EPSSArgs) Kind() string { return "feeds_epss" }

// insertOpts keeps at most one unfinished job per kind, so a long bootstrap
// doesn't pile up periodic duplicates.
func insertOpts() *river.InsertOpts {
	return &river.InsertOpts{MaxAttempts: 3, UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
		rivertype.JobStateRetryable, rivertype.JobStateScheduled,
	}}}
}

// PeriodicJobs schedules OSV every 15m, KEV hourly and EPSS daily, each also on start.
func PeriodicJobs() []*river.PeriodicJob {
	job := func(every time.Duration, args river.JobArgs) *river.PeriodicJob {
		return river.NewPeriodicJob(river.PeriodicInterval(every),
			func() (river.JobArgs, *river.InsertOpts) { return args, insertOpts() },
			&river.PeriodicJobOpts{ID: args.Kind(), RunOnStart: true})
	}
	return []*river.PeriodicJob{
		job(15*time.Minute, OSVArgs{}),
		job(time.Hour, KEVArgs{}),
		job(24*time.Hour, EPSSArgs{}),
	}
}

// AddWorkers registers the feeds_osv, feeds_kev and feeds_epss workers.
func AddWorkers(w *river.Workers, pool *pgxpool.Pool) {
	s := New(pool, Options{})
	river.AddWorker(w, &osvWorker{s: s})
	river.AddWorker(w, &kevWorker{s: s})
	river.AddWorker(w, &epssWorker{s: s})
}

type osvWorker struct {
	river.WorkerDefaults[OSVArgs]
	s *Syncer
}

func (w *osvWorker) Work(ctx context.Context, j *river.Job[OSVArgs]) error {
	return w.s.SyncAllOSV(ctx, j.Args.Ecosystems)
}

// Timeout allows a full npm all.zip bootstrap.
func (w *osvWorker) Timeout(*river.Job[OSVArgs]) time.Duration { return 2 * time.Hour }

type kevWorker struct {
	river.WorkerDefaults[KEVArgs]
	s *Syncer
}

func (w *kevWorker) Work(ctx context.Context, _ *river.Job[KEVArgs]) error { return w.s.SyncKEV(ctx) }
func (w *kevWorker) Timeout(*river.Job[KEVArgs]) time.Duration             { return 5 * time.Minute }

type epssWorker struct {
	river.WorkerDefaults[EPSSArgs]
	s *Syncer
}

func (w *epssWorker) Work(ctx context.Context, _ *river.Job[EPSSArgs]) error {
	return w.s.SyncEPSS(ctx)
}
func (w *epssWorker) Timeout(*river.Job[EPSSArgs]) time.Duration { return 15 * time.Minute }
