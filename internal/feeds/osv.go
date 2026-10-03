package feeds

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
	"golang.org/x/sync/errgroup"
)

// Severity is one entry of an OSV record's severity[].
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvRecord struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Aliases          []string       `json:"aliases"`
	Published        string         `json:"published"`
	Modified         string         `json:"modified"`
	Withdrawn        string         `json:"withdrawn"`
	Severity         []Severity     `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
	Affected         []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Versions []string        `json:"versions"`
		Ranges   json.RawMessage `json:"ranges"`
	} `json:"affected"`
}

var pep503 = regexp.MustCompile(`[-_.]+`)

// NormalizeName returns the lookup key for a package name in an OSV
// ecosystem: PEP 503 for PyPI, lowercase for npm, unchanged otherwise.
func NormalizeName(ecosystem, name string) string {
	switch ecosystem {
	case "PyPI":
		return pep503.ReplaceAllString(strings.ToLower(name), "-")
	case "npm":
		return strings.ToLower(name)
	}
	return name
}

// BestCVSS returns the highest CVSS v3.x/v4 base score in severity[] and
// its vector; score is 0 when none parses.
func BestCVSS(sev []Severity) (score float64, vector string) {
	for _, s := range sev {
		var v float64
		switch {
		case strings.HasPrefix(s.Score, "CVSS:3.1/"):
			if c, err := gocvss31.ParseVector(s.Score); err == nil {
				v = c.BaseScore()
			}
		case strings.HasPrefix(s.Score, "CVSS:3.0/"):
			if c, err := gocvss30.ParseVector(s.Score); err == nil {
				v = c.BaseScore()
			}
		case strings.HasPrefix(s.Score, "CVSS:4.0/"):
			if c, err := gocvss40.ParseVector(s.Score); err == nil {
				v = c.Score()
			}
		}
		if v > score {
			score, vector = v, s.Score
		}
	}
	return score, vector
}

// Risk derives CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN for an advisory: MAL-* is
// CRITICAL, else the best CVSS base score, else database_specific.severity.
func Risk(id string, sev []Severity, dbSeverity string) string {
	if strings.HasPrefix(id, "MAL-") {
		return "CRITICAL"
	}
	switch score, _ := BestCVSS(sev); {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	}
	switch strings.ToUpper(dbSeverity) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MODERATE", "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	}
	return "UNKNOWN"
}

func ts(s string) pgtype.Timestamptz {
	t, err := time.Parse(time.RFC3339Nano, s)
	return pgtype.Timestamptz{Time: t, Valid: err == nil}
}

// Ingest upserts raw OSV JSON records (one advisory each) and replaces their
// affected and alias rows. source is the OSV bucket directory (ecosystem).
// Unparseable records are logged and skipped.
func (s *Syncer) Ingest(ctx context.Context, source string, raws [][]byte) error {
	var (
		ids, sums, dets, sevs, risks, rawc []string
		pubs, mods, wds                    []pgtype.Timestamptz
		afA, afE, afN, afV, afR            []string
		alA, alX                           []string
		seen                               = map[string]bool{}
	)
	for _, raw := range raws {
		// Postgres jsonb/text reject NUL and invalid UTF-8.
		clean := strings.ToValidUTF8(string(stripNUL(raw)), "\uFFFD")
		var r osvRecord
		if err := json.Unmarshal([]byte(clean), &r); err != nil || r.ID == "" || seen[r.ID] {
			if err != nil {
				s.o.Logger.Warn("osv: skip unparseable record", "source", source, "err", err)
			}
			continue
		}
		seen[r.ID] = true
		dbSev, _ := r.DatabaseSpecific["severity"].(string)
		sevJSON, _ := json.Marshal(r.Severity)
		if r.Severity == nil {
			sevJSON = []byte("[]")
		}
		mod := ts(r.Modified)
		if !mod.Valid {
			mod = ts(r.Published)
		}
		if !mod.Valid {
			mod = pgtype.Timestamptz{Time: time.Unix(0, 0), Valid: true}
		}
		ids, sums, dets = append(ids, r.ID), append(sums, r.Summary), append(dets, r.Details)
		sevs, risks, rawc = append(sevs, string(sevJSON)), append(risks, Risk(r.ID, r.Severity, dbSev)), append(rawc, clean)
		pubs, mods, wds = append(pubs, ts(r.Published)), append(mods, mod), append(wds, ts(r.Withdrawn))
		for _, a := range r.Affected {
			if a.Package.Name == "" {
				continue
			}
			vers, _ := json.Marshal(a.Versions)
			if a.Versions == nil {
				vers = []byte("[]")
			}
			rng := string(a.Ranges)
			if rng == "" || rng == "null" {
				rng = "[]"
			}
			afA, afE, afN = append(afA, r.ID), append(afE, a.Package.Ecosystem), append(afN, NormalizeName(a.Package.Ecosystem, a.Package.Name))
			afV, afR = append(afV, string(vers)), append(afR, rng)
		}
		for _, al := range r.Aliases {
			alA, alX = append(alA, r.ID), append(alX, al)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	b.Queue(`INSERT INTO advisory (id, source, summary, details, severity, risk, published, modified, withdrawn, raw)
		SELECT t.id, $2, NULLIF(t.s, ''), NULLIF(t.d, ''), t.sev::jsonb, t.risk, t.pub, t.mod, t.wd, t.raw::jsonb
		FROM unnest($1::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[], $8::timestamptz[], $9::timestamptz[], $10::text[])
		  AS t(id, s, d, sev, risk, pub, mod, wd, raw)
		ON CONFLICT (id) DO UPDATE SET source = EXCLUDED.source, summary = EXCLUDED.summary, details = EXCLUDED.details,
		  severity = EXCLUDED.severity, risk = EXCLUDED.risk, published = EXCLUDED.published, modified = EXCLUDED.modified,
		  withdrawn = EXCLUDED.withdrawn, raw = EXCLUDED.raw`,
		ids, source, sums, dets, sevs, risks, pubs, mods, wds, rawc)
	b.Queue(`DELETE FROM affected WHERE advisory_id = ANY($1)`, ids)
	b.Queue(`INSERT INTO affected (advisory_id, ecosystem, name_norm, versions, ranges)
		SELECT a, e, n, ARRAY(SELECT jsonb_array_elements_text(v::jsonb)), r::jsonb
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[]) AS t(a, e, n, v, r)`,
		afA, afE, afN, afV, afR)
	b.Queue(`DELETE FROM advisory_alias WHERE advisory_id = ANY($1)`, ids)
	b.Queue(`INSERT INTO advisory_alias (advisory_id, alias)
		SELECT a, x FROM unnest($1::text[], $2::text[]) AS t(a, x) ON CONFLICT DO NOTHING`, alA, alX)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return tx.SendBatch(ctx, b).Close()
	})
}

// stripNUL drops JSON \u0000 escapes (rejected by Postgres jsonb), leaving
// an escaped backslash followed by "u0000" intact.
func stripNUL(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\u0000`)) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		switch {
		case bytes.HasPrefix(b[i:], []byte(`\u0000`)):
			i += 5
		case b[i] == '\\' && i+1 < len(b): // copy escape pairs whole, so `\\u0000` survives
			out = append(out, b[i], b[i+1])
			i++
		default:
			out = append(out, b[i])
		}
	}
	return out
}

const ingestChunk = 500

var errTooMany = errors.New("too many changes for incremental sync")

func (s *Syncer) osvURL(eco, file string) string {
	return s.o.OSVBaseURL + "/" + url.PathEscape(eco) + "/" + file
}

// SyncOSV syncs one OSV ecosystem: incremental from modified_id.csv when a
// cursor exists, else (or when too far behind) a full all.zip bootstrap.
func (s *Syncer) SyncOSV(ctx context.Context, eco string) error {
	return s.run(ctx, "osv:"+eco, func(cursor, _ string) (string, string, error) {
		if cursor != "" {
			cur, err := s.osvIncremental(ctx, eco, cursor)
			if !errors.Is(err, errTooMany) {
				return cur, "", err
			}
			s.o.Logger.Info("osv: too far behind, re-bootstrapping", "ecosystem", eco)
		}
		cur, err := s.osvBootstrap(ctx, eco)
		return cur, "", err
	})
}

func (s *Syncer) get(ctx context.Context, u string, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.o.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		resp.Body.Close()
		return nil, &httpError{u, resp.StatusCode}
	}
	return resp, nil
}

type httpError struct {
	url  string
	code int
}

func (e *httpError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.url, e.code) }

// changedSince streams modified_id.csv (newest first) and returns ids
// modified after cursor plus the newest timestamp. Empty cursor = only head.
func (s *Syncer) changedSince(ctx context.Context, eco, cursor string) (ids []string, head string, err error) {
	resp, err := s.get(ctx, s.osvURL(eco, "modified_id.csv"), nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close() // stop reading early: we only need rows newer than cursor
	var cur time.Time
	if cursor != "" {
		if cur, err = time.Parse(time.RFC3339Nano, cursor); err != nil {
			return nil, "", fmt.Errorf("bad cursor %q: %w", cursor, err)
		}
	}
	seen := map[string]bool{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		tsStr, id, ok := strings.Cut(strings.TrimSpace(sc.Text()), ",")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			continue
		}
		if head == "" {
			head = tsStr
		}
		if cursor == "" || !t.After(cur) {
			break
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
			if len(ids) > s.o.MaxIncremental {
				return nil, "", errTooMany
			}
		}
	}
	return ids, head, sc.Err()
}

func (s *Syncer) osvIncremental(ctx context.Context, eco, cursor string) (string, error) {
	ids, head, err := s.changedSince(ctx, eco, cursor)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return cursor, nil
	}
	raws := make([][]byte, len(ids))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(8)
	for i, id := range ids {
		g.Go(func() error {
			resp, err := s.get(gctx, s.osvURL(eco, url.PathEscape(id)+".json"), nil)
			var he *httpError
			if errors.As(err, &he) && he.code == http.StatusNotFound {
				return nil // listed but gone; skip
			}
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			raws[i], err = io.ReadAll(resp.Body)
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return "", err
	}
	for i := 0; i < len(raws); i += ingestChunk {
		if err := s.Ingest(ctx, eco, raws[i:min(i+ingestChunk, len(raws))]); err != nil {
			return "", err
		}
	}
	s.o.Logger.Info("osv: incremental sync", "ecosystem", eco, "records", len(ids))
	return head, nil
}

func (s *Syncer) osvBootstrap(ctx context.Context, eco string) (string, error) {
	start := time.Now()
	// Take the cursor before downloading so changes during the download are
	// picked up by the next incremental run.
	_, head, err := s.changedSince(ctx, eco, "")
	if err != nil {
		return "", err
	}
	if head == "" {
		head = start.UTC().Format(time.RFC3339Nano)
	}
	f, err := os.CreateTemp("", "osv-*.zip")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	resp, err := s.get(ctx, s.osvURL(eco, "all.zip"), nil)
	if err != nil {
		return "", err
	}
	size, err := io.Copy(f, resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return "", err
	}
	var chunk [][]byte
	n := 0
	for _, zf := range zr.File {
		if !strings.HasSuffix(zf.Name, ".json") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return "", err
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return "", err
		}
		if chunk = append(chunk, raw); len(chunk) == ingestChunk {
			if err := s.Ingest(ctx, eco, chunk); err != nil {
				return "", err
			}
			n, chunk = n+len(chunk), chunk[:0]
		}
	}
	if err := s.Ingest(ctx, eco, chunk); err != nil {
		return "", err
	}
	n += len(chunk)
	s.o.Logger.Info("osv: bootstrap done", "ecosystem", eco, "records", n, "zip_bytes", size, "took", time.Since(start).Round(time.Millisecond))
	return head, nil
}
