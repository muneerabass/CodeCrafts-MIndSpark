// Command depguard-feeds bootstraps or manually syncs the vulnerability feeds
// (normally run by River periodic jobs in the worker).
//
//	depguard-feeds sync [--ecosystems npm,PyPI] [--sources osv,kev,epss] [--once]
//	depguard-feeds status
//
// DATABASE_URL must point at a migrated database (depguard_app role is enough).
// Without --once, sync keeps running: OSV every 15m, KEV hourly, EPSS daily.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/feeds"
)

func main() {
	if err := run(); err != nil {
		slog.Error("depguard-feeds", "err", err)
		os.Exit(1)
	}
}

func usage() error {
	return fmt.Errorf("usage: depguard-feeds sync [--ecosystems npm,PyPI] [--sources osv,kev,epss] [--once] | status")
}

func run() error {
	if len(os.Args) < 2 {
		return usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	switch os.Args[1] {
	case "status":
		st, err := feeds.Status(ctx, pool)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	case "sync":
		fs := flag.NewFlagSet("sync", flag.ExitOnError)
		ecos := fs.String("ecosystems", "", "comma-separated OSV ecosystems (default: all supported)")
		sources := fs.String("sources", "osv,kev,epss", "comma-separated sources")
		once := fs.Bool("once", false, "sync once and exit")
		fs.Parse(os.Args[2:])
		var opts feeds.Options
		if *ecos != "" {
			opts.Ecosystems = strings.Split(*ecos, ",")
		}
		s := feeds.New(pool, opts)
		want := map[string]bool{}
		for _, x := range strings.Split(*sources, ",") {
			want[strings.TrimSpace(x)] = true
		}
		jobs := []struct {
			name  string
			every time.Duration
			fn    func(context.Context) error
		}{
			{"osv", 15 * time.Minute, func(ctx context.Context) error { return s.SyncAllOSV(ctx, nil) }},
			{"kev", time.Hour, s.SyncKEV},
			{"epss", 24 * time.Hour, s.SyncEPSS},
		}
		last := map[string]time.Time{}
		var failed bool
		for {
			for _, j := range jobs {
				if !want[j.name] || time.Since(last[j.name]) < j.every {
					continue
				}
				start := time.Now()
				err := j.fn(ctx)
				last[j.name] = start
				if err != nil {
					failed = true
					slog.Error("sync failed", "source", j.name, "err", err)
				} else {
					slog.Info("sync ok", "source", j.name, "took", time.Since(start).Round(time.Millisecond))
				}
			}
			if *once {
				if failed {
					return fmt.Errorf("one or more sources failed")
				}
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Minute):
			}
		}
	}
	return usage()
}
