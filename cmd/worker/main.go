// Command worker runs depguard's River workers: scans (PR, repository,
// upload), guarddog analysis, GitHub installation sync, feed sync and
// webhook redelivery. Migrations are run by the api.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/engine"
	"github.com/depguard/depguard/internal/enrich"
	"github.com/depguard/depguard/internal/feeds"
	"github.com/depguard/depguard/internal/ghapp"
	"github.com/depguard/depguard/internal/license"
	"github.com/depguard/depguard/internal/suspicious"
	"github.com/palantir/go-githubapp/githubapp"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

func main() {
	var level slog.Level
	_ = level.UnmarshalText([]byte(os.Getenv("LOG_LEVEL")))
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	if err := run(log); err != nil {
		log.Error("worker exited", "err", err)
		os.Exit(1)
	}
}

func envBool(k string) bool { b, _ := strconv.ParseBool(os.Getenv(k)); return b }

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer pool.Close()

	ghcfg, err := ghapp.ConfigFromEnv()
	if err != nil {
		return err
	}
	var clients githubapp.ClientCreator
	if ghcfg.AppID != 0 {
		if clients, err = ghapp.NewClientCreator(ghcfg); err != nil {
			return err
		}
	} else {
		log.Warn("GITHUB_APP_ID not set: GitHub scans will be cancelled")
	}

	enricher := enrich.New(pool, enrich.Options{
		DisableDepsDev:   envBool("DEPSDEV_DISABLED"),
		DisableScorecard: envBool("SCORECARD_DISABLED"),
		Logger:           log,
	})
	guarddogJobs, _ := strconv.Atoi(os.Getenv("GUARDDOG_MAX_JOBS")) // 0 = default 25
	workers := river.NewWorkers()
	engine.AddWorkers(workers, engine.Deps{
		Pool:                   pool,
		Clients:                clients,
		GitHub:                 ghcfg,
		Enricher:               enricher,
		PublicURL:              os.Getenv("PUBLIC_URL"),
		GuarddogBin:            envOr("GUARDDOG_BIN", "guarddog"),
		GuarddogAllowNoSandbox: envBool("GUARDDOG_ALLOW_NO_SANDBOX"),
		DisableXBOM:            envBool("XBOM_DISABLED"),
		Checkers:               engine.StandardCheckers(pool, enricher),
		DetectLicense: func(files map[string][]byte, githubSPDX string) (string, string) {
			d := license.DetectProject(files, githubSPDX)
			return d.Expr, d.Source
		},
		PrioritizeGuarddog: suspicious.Prioritize,
		MaxGuarddogJobs:    guarddogJobs,
		Logger:             log,
	})
	feeds.AddWorkers(workers, pool)
	periodic := feeds.PeriodicJobs()
	if clients != nil {
		ghapp.AddWorkers(workers, ghcfg)
		periodic = append(periodic, ghapp.PeriodicJobs()...)
	}

	concurrency, _ := strconv.Atoi(envOr("WORKER_CONCURRENCY", "10"))
	rc, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:       map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: max(concurrency, 1)}},
		Workers:      workers,
		PeriodicJobs: periodic,
		MaxAttempts:  5,
		Logger:       log,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			http.Error(w, "db unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: envOr("WORKER_HEALTH_ADDR", ":8081"), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health server", "err", err)
			stop()
		}
	}()

	if err := rc.Start(ctx); err != nil {
		return err
	}
	log.Info("worker started", "concurrency", concurrency)
	<-ctx.Done()

	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rc.Stop(sctx); err != nil {
		log.Warn("graceful stop timed out, cancelling running jobs", "err", err)
		hard, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel2()
		_ = rc.StopAndCancel(hard)
	}
	return srv.Shutdown(sctx)
}
