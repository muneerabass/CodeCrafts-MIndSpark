// Package ghapp is the GitHub App integration: config and clients, webhook
// intake (verify, dedupe, enqueue), install URL and webhook redelivery.
package ghapp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofri/go-github-ratelimit/v2/github_ratelimit"
	"github.com/google/go-github/v92/github"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/riverqueue/river"
)

const DefaultCheckRunName = "depguard: Supply Chain Security"

// Config is the GitHub App configuration (env GITHUB_*, CHECK_RUN_NAME).
type Config struct {
	AppID         int64
	Slug          string
	PrivateKey    []byte // PEM
	WebhookSecret string
	APIURL        string // REST base URL, default https://api.github.com/
	CheckRunName  string
}

// ConfigFromEnv reads GITHUB_APP_ID, GITHUB_APP_SLUG, GITHUB_APP_PRIVATE_KEY
// (PEM contents or a file path), GITHUB_WEBHOOK_SECRET, GITHUB_API_URL, CHECK_RUN_NAME.
func ConfigFromEnv() (Config, error) {
	c := Config{
		Slug:          os.Getenv("GITHUB_APP_SLUG"),
		WebhookSecret: os.Getenv("GITHUB_WEBHOOK_SECRET"),
		APIURL:        os.Getenv("GITHUB_API_URL"),
		CheckRunName:  os.Getenv("CHECK_RUN_NAME"),
	}
	if v := os.Getenv("GITHUB_APP_ID"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return c, fmt.Errorf("GITHUB_APP_ID: %w", err)
		}
		c.AppID = id
	}
	key, err := LoadPrivateKey(os.Getenv("GITHUB_APP_PRIVATE_KEY"))
	if err != nil {
		return c, err
	}
	c.PrivateKey = key
	return c.withDefaults(), nil
}

// LoadPrivateKey accepts PEM contents (literal "\n" escapes allowed) or a path.
func LoadPrivateKey(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return nil, nil
	case strings.HasPrefix(v, "-----BEGIN"):
		return []byte(strings.ReplaceAll(v, `\n`, "\n")), nil
	default:
		b, err := os.ReadFile(v)
		if err != nil {
			return nil, fmt.Errorf("GITHUB_APP_PRIVATE_KEY: %w", err)
		}
		return b, nil
	}
}

func (c Config) withDefaults() Config {
	if c.APIURL == "" {
		c.APIURL = "https://api.github.com/"
	}
	if !strings.HasSuffix(c.APIURL, "/") {
		c.APIURL += "/"
	}
	if c.CheckRunName == "" {
		c.CheckRunName = DefaultCheckRunName
	}
	return c
}

// InstallURL is where an org admin installs the app.
func InstallURL(cfg Config) string {
	return "https://github.com/apps/" + cfg.Slug + "/installations/new"
}

// NewClientCreator builds app/installation clients with cached installation
// tokens (go-githubapp) and primary/secondary rate-limit handling.
func NewClientCreator(cfg Config) (githubapp.ClientCreator, error) {
	cfg = cfg.withDefaults()
	if cfg.AppID == 0 || len(cfg.PrivateKey) == 0 {
		return nil, errors.New("ghapp: GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY are required")
	}
	cc := githubapp.NewClientCreator(cfg.APIURL, strings.TrimSuffix(cfg.APIURL, "/")+"/graphql", cfg.AppID, cfg.PrivateKey,
		githubapp.WithClientUserAgent("depguard"),
		githubapp.WithClientTimeout(60*time.Second),
		githubapp.WithClientMiddleware(func(next http.RoundTripper) http.RoundTripper {
			return github_ratelimit.New(next)
		}),
	)
	return githubapp.NewCachingClientCreator(cc, githubapp.DefaultCachingClientCapacity)
}

// Redeliver asks GitHub to resend a delivery by its X-GitHub-Delivery GUID.
func Redeliver(ctx context.Context, cfg Config, deliveryID string) error {
	cc, err := NewClientCreator(cfg)
	if err != nil {
		return err
	}
	app, err := cc.NewAppClient()
	if err != nil {
		return err
	}
	n := 0
	for d, err := range app.Apps.ListHookDeliveriesIter(ctx, &github.ListCursorOptions{PerPage: 100}) {
		if err != nil {
			return err
		}
		if d.GetGUID() == deliveryID {
			_, _, err := app.Apps.RedeliverHookDelivery(ctx, d.GetID())
			return err
		}
		if n++; n >= 2000 {
			break
		}
	}
	return fmt.Errorf("ghapp: delivery %s not found in recent deliveries", deliveryID)
}

// RedeliverFailed is a periodic job: redeliver deliveries GitHub reports as
// failed in the last 24h (max 5 attempts per delivery, 50 per run).
type RedeliverFailed struct{}

func (RedeliverFailed) Kind() string { return "github_redeliver_failed" }

type redeliverWorker struct {
	river.WorkerDefaults[RedeliverFailed]
	cfg Config
}

func (w *redeliverWorker) Work(ctx context.Context, _ *river.Job[RedeliverFailed]) error {
	cc, err := NewClientCreator(w.cfg)
	if err != nil {
		return river.JobCancel(err) // not configured
	}
	app, err := cc.NewAppClient()
	if err != nil {
		return err
	}
	return redeliverFailed(ctx, app, time.Now().Add(-24*time.Hour))
}

func redeliverFailed(ctx context.Context, app *github.Client, since time.Time) error {
	type state struct {
		ok       bool
		attempts int
		latest   int64
	}
	byGUID := map[string]*state{}
	var order []string
	for d, err := range app.Apps.ListHookDeliveriesIter(ctx, &github.ListCursorOptions{PerPage: 100}) {
		if err != nil {
			return err
		}
		if d.GetDeliveredAt().Before(since) {
			break // newest first
		}
		s := byGUID[d.GetGUID()]
		if s == nil {
			s = &state{latest: d.GetID()}
			byGUID[d.GetGUID()] = s
			order = append(order, d.GetGUID())
		}
		s.attempts++
		if c := d.GetStatusCode(); c >= 200 && c < 300 {
			s.ok = true
		}
	}
	sent := 0
	for _, g := range order {
		s := byGUID[g]
		if s.ok || s.attempts >= 5 || sent >= 50 {
			continue
		}
		if _, _, err := app.Apps.RedeliverHookDelivery(ctx, s.latest); err != nil {
			return err
		}
		sent++
	}
	return nil
}

// AddWorkers registers ghapp's own jobs (webhook redelivery).
func AddWorkers(w *river.Workers, cfg Config) {
	river.AddWorker(w, &redeliverWorker{cfg: cfg})
}

// PeriodicJobs schedules failed-delivery redelivery every 30 minutes.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(30*time.Minute),
		func() (river.JobArgs, *river.InsertOpts) { return RedeliverFailed{}, nil },
		&river.PeriodicJobOpts{ID: "github_redeliver_failed"})}
}
