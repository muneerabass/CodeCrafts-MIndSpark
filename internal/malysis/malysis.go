// Package malysis queries SafeDep's community malware analysis service (the
// service behind safedep/pmg and vet --malware) for install-time checks, with
// verdicts cached in Postgres so a package version is looked up once.
package malysis

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/safedep/vet/pkg/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/depguard/depguard/internal/db"
)

const (
	communityAddr = "community-api.safedep.io:443"
	cacheTTL      = 24 * time.Hour
	perCall       = 5 * time.Second
	workers       = 8
)

// Verdict is the service's answer for one package version.
type Verdict struct {
	Malware    bool   // flagged by analysis (may be unverified)
	Verified   bool   // confirmed malicious by SafeDep
	AnalysisID string // report: https://app.safedep.io/community/malysis/<id>
	Summary    string
}

// ReportURL links to the public analysis report.
func (v Verdict) ReportURL() string {
	if v.AnalysisID == "" {
		return ""
	}
	return "https://app.safedep.io/community/malysis/" + v.AnalysisID
}

type Client struct {
	pool   *pgxpool.Pool
	client malysisv1grpc.MalwareAnalysisServiceClient
}

// New dials the community service lazily (no network until the first query).
func New(pool *pgxpool.Pool) (*Client, error) {
	cc, err := grpc.NewClient(communityAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
	if err != nil {
		return nil, err
	}
	return &Client{pool: pool, client: malysisv1grpc.NewMalwareAnalysisServiceClient(cc)}, nil
}

type key struct{ eco, name, version string }

// Query returns verdicts for the packages that the service knows about.
// Lookups that fail or time out are skipped: this is an extra signal on top of
// the OSV malware feed, never a reason to fail a check.
func (c *Client) Query(ctx context.Context, pkgs []*models.Package) map[*models.Package]Verdict {
	out := map[*models.Package]Verdict{}
	if c == nil || len(pkgs) == 0 {
		return out
	}
	byKey := map[key][]*models.Package{}
	for _, p := range pkgs {
		if p.GetControlTowerSpecEcosystem() == packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED {
			continue
		}
		k := key{string(p.GetControlTowerSpecEcosystem()), p.GetName(), p.GetVersion()}
		byKey[k] = append(byKey[k], p)
	}
	cached := c.cached(ctx, byKey)
	var mu sync.Mutex
	set := func(k key, v Verdict) {
		mu.Lock()
		for _, p := range byKey[k] {
			out[p] = v
		}
		mu.Unlock()
	}
	jobs := make(chan key)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range jobs {
				v, err := c.lookup(ctx, byKey[k][0])
				if err != nil {
					continue
				}
				set(k, v)
				c.store(ctx, k, v)
			}
		}()
	}
	for k := range byKey {
		if v, ok := cached[k]; ok {
			set(k, v)
			continue
		}
		select {
		case jobs <- k:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

func (c *Client) lookup(ctx context.Context, p *models.Package) (Verdict, error) {
	cctx, cancel := context.WithTimeout(ctx, perCall)
	defer cancel()
	res, err := c.client.QueryPackageAnalysis(cctx, &malysisv1.QueryPackageAnalysisRequest{
		Target: &malysisv1pb.PackageAnalysisTarget{PackageVersion: &packagev1.PackageVersion{
			Package: &packagev1.Package{Ecosystem: p.GetControlTowerSpecEcosystem(), Name: p.GetName()},
			Version: p.GetVersion(),
		}},
	})
	if err != nil {
		return Verdict{}, err
	}
	if res.GetAnalysisId() == "" {
		return Verdict{}, nil // never analysed: no signal, cache as clean
	}
	return Verdict{
		Malware:    res.GetReport().GetInference().GetIsMalware() || res.GetVerificationRecord().GetIsMalware(),
		Verified:   res.GetVerificationRecord().GetIsMalware(),
		AnalysisID: res.GetAnalysisId(),
		Summary:    res.GetReport().GetInference().GetSummary(),
	}, nil
}

func (c *Client) cached(ctx context.Context, keys map[key][]*models.Package) map[key]Verdict {
	out := map[key]Verdict{}
	if c.pool == nil {
		return out
	}
	var ecos, names, versions []string
	for k := range keys {
		ecos, names, versions = append(ecos, k.eco), append(names, k.name), append(versions, k.version)
	}
	_ = db.WithSystemTx(ctx, c.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT m.ecosystem, m.name, m.version, m.is_malware, m.verified, m.analysis_id, m.summary
			FROM malysis_verdict m JOIN unnest($1::text[], $2::text[], $3::text[]) AS q(e, n, v)
			  ON m.ecosystem = q.e AND m.name = q.n AND m.version = q.v
			WHERE m.fetched_at > now() - $4::interval`, ecos, names, versions, cacheTTL.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k key
			var v Verdict
			if err := rows.Scan(&k.eco, &k.name, &k.version, &v.Malware, &v.Verified, &v.AnalysisID, &v.Summary); err != nil {
				return err
			}
			out[k] = v
		}
		return rows.Err()
	})
	return out
}

func (c *Client) store(ctx context.Context, k key, v Verdict) {
	if c.pool == nil {
		return
	}
	err := db.WithSystemTx(ctx, c.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO malysis_verdict (ecosystem, name, version, is_malware, verified, analysis_id, summary, fetched_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,now())
			ON CONFLICT (ecosystem, name, version) DO UPDATE SET is_malware=EXCLUDED.is_malware, verified=EXCLUDED.verified,
			  analysis_id=EXCLUDED.analysis_id, summary=EXCLUDED.summary, fetched_at=now()`,
			k.eco, k.name, k.version, v.Malware, v.Verified, v.AnalysisID, v.Summary)
		return err
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return
	}
}
