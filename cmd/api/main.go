// Command api serves the depguard HTTP API (web REST, machine ingest, MCP,
// GitHub webhooks, River UI). `api healthcheck` probes a running instance.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/ghapp"
	"github.com/depguard/depguard/internal/httpapi"
	"github.com/depguard/depguard/internal/httpapi/riverdb"
	"github.com/depguard/depguard/internal/ids"
	"github.com/depguard/depguard/internal/mcpserver"
	"github.com/depguard/depguard/internal/query"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"riverqueue.com/riverui"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	migrate := flag.Bool("migrate", envBool("MIGRATE_ON_START", true), "run database + River migrations before serving (env MIGRATE_ON_START)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log, *migrate); err != nil {
		log.Error("api exited", "err", err)
		os.Exit(1)
	}
}

func addr() string { return env("HTTP_ADDR", ":8080") }

// healthcheck GETs /healthz on the local listener (distroless image has no curl).
func healthcheck() int {
	a := addr()
	if strings.HasPrefix(a, ":") {
		a = "127.0.0.1" + a
	}
	c := &http.Client{Timeout: 3 * time.Second}
	res, err := c.Get("http://" + a + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "status", res.StatusCode)
		return 1
	}
	return 0
}

func run(ctx context.Context, log *slog.Logger, migrate bool) error {
	appDSN, ownerDSN, queryDSN := os.Getenv("DATABASE_URL"), os.Getenv("DATABASE_OWNER_URL"), os.Getenv("DATABASE_QUERY_URL")
	secret := os.Getenv("SERVICE_JWT_SECRET")
	if appDSN == "" || queryDSN == "" || len(secret) < 32 {
		return errors.New("DATABASE_URL, DATABASE_QUERY_URL and SERVICE_JWT_SECRET (>= 32 chars) are required")
	}
	if migrate {
		if ownerDSN == "" {
			return errors.New("DATABASE_OWNER_URL is required for migrations (or run with -migrate=false)")
		}
		if err := db.Migrate(ctx, ownerDSN); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if err := riverdb.Migrate(ctx, ownerDSN); err != nil {
			return err
		}
		log.Info("migrations applied")
	}
	pool, err := db.Open(ctx, appDSN)
	if err != nil {
		return fmt.Errorf("open app db: %w", err)
	}
	defer pool.Close()
	qpool, err := db.Open(ctx, queryDSN)
	if err != nil {
		return fmt.Errorf("open query db: %w", err)
	}
	defer qpool.Close()
	jobs, err := riverdb.NewInserter(pool)
	if err != nil {
		return err
	}

	ghCfg, err := ghapp.ConfigFromEnv()
	if err != nil {
		return err
	}
	ui, err := riverui.NewHandler(&riverui.HandlerOpts{Endpoints: riverui.NewEndpoints(jobs, nil), Logger: log, Prefix: "/admin/river"})
	if err != nil {
		return fmt.Errorf("river ui: %w", err)
	}
	if err := ui.Start(ctx); err != nil {
		return fmt.Errorf("river ui: %w", err)
	}
	enr := enrich.New(pool, enrich.Options{
		DisableDepsDev: envBool("DEPSDEV_DISABLED", false), DisableScorecard: envBool("SCORECARD_DISABLED", false), Logger: log,
	})

	api := httpapi.New(httpapi.Deps{
		Pool: pool, Jobs: jobs, JobOpts: ghapp.JobOpts, Query: &query.Executor{Pool: qpool}, JWTSecret: []byte(secret),
		PublicURL: env("PUBLIC_URL", "http://localhost:3000"), PublicAPIURL: os.Getenv("PUBLIC_API_URL"), Logger: log,
		GitHubInstallURL: func() string { return ghapp.InstallURL(ghCfg) },
		Redeliver:        func(ctx context.Context, id string) error { return ghapp.Redeliver(ctx, ghCfg, id) },
		FeedsStatus:      func(ctx context.Context) (any, error) { return feeds.Status(ctx, pool) },
		Webhook:          ghapp.NewWebhookHandler(ghapp.Deps{Pool: pool, River: jobs, Config: ghCfg, Logger: log}),
		MCP:              mcpserver.Handler(pool, enr),
		RiverUI:          ui,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		c, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(c); err != nil {
			http.Error(w, "db unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.Handle("/", api)

	srv := &http.Server{
		Addr:              addr(),
		Handler:           withRequestLog(log, mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute, // 50 MB uploads
		WriteTimeout:      2 * time.Minute, // /v1/scans?wait=true extends its own deadline
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

var (
	reqTotal = promauto.NewCounterVec(prometheus.CounterOpts{Name: "depguard_http_requests_total", Help: "HTTP requests."}, []string{"method", "code"})
	reqDur   = promauto.NewHistogram(prometheus.HistogramOpts{Name: "depguard_http_request_duration_seconds", Help: "HTTP request latency."})
)

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int)        { w.code = code; w.ResponseWriter.WriteHeader(code) }
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withRequestLog assigns X-Request-ID, logs each request and records metrics.
func withRequestLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 100 {
			id = ids.New()
		}
		w.Header().Set("X-Request-ID", id)
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		d := time.Since(start)
		reqTotal.WithLabelValues(r.Method, strconv.Itoa(sw.code)).Inc()
		reqDur.Observe(d.Seconds())
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			return
		}
		log.Info("request", "request_id", id, "method", r.Method, "path", r.URL.Path, "status", sw.code, "duration_ms", d.Milliseconds())
	})
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	if b, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return b
	}
	return def
}

func logLevel() slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(env("LOG_LEVEL", "info"))); err != nil {
		return slog.LevelInfo
	}
	return l
}
