package engine

import (
	"context"
	"time"

	"github.com/depguard/depguard/internal/alerts"
	"github.com/depguard/depguard/internal/db"
	"github.com/depguard/depguard/internal/jobs"
	"github.com/depguard/depguard/internal/notify"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

type notifyWorker struct {
	river.WorkerDefaults[jobs.Notify]
	d Deps
}

// build runs fn with the tenant's channels and sends + records what it returns.
func (d Deps) sendAlert(ctx context.Context, tenant string, fn func(tx pgx.Tx, ch alerts.Channels) (notify.Message, []alerts.Item, error)) error {
	var ch alerts.Channels
	var m notify.Message
	var items []alerts.Item
	err := withTenant(ctx, d, tenant, func(tx pgx.Tx) error {
		var err error
		if ch, err = alerts.Load(ctx, tx, tenant); err != nil || !ch.Any(d.SMTP) {
			return err
		}
		m, items, err = fn(tx, ch)
		return err
	})
	if err != nil || len(items) == 0 {
		return err
	}
	if err := ch.Send(ctx, d.SMTP, m); err != nil {
		return err // retried by River
	}
	return withTenant(ctx, d, tenant, func(tx pgx.Tx) error { return alerts.MarkSent(ctx, tx, tenant, items) })
}

func (w *notifyWorker) Work(ctx context.Context, job *river.Job[jobs.Notify]) error {
	a := job.Args
	return w.d.sendAlert(ctx, a.TenantID, func(tx pgx.Tx, ch alerts.Channels) (notify.Message, []alerts.Item, error) {
		if a.PRID != "" {
			return alerts.PRAlert(ctx, tx, ch, a.PRID, w.d.PublicURL)
		}
		return alerts.ScanAlert(ctx, tx, ch, a.ScanID, w.d.PublicURL)
	})
}

type dailyAlertsWorker struct {
	river.WorkerDefaults[jobs.DailyAlerts]
	d Deps
}

func (w *dailyAlertsWorker) Work(ctx context.Context, _ *river.Job[jobs.DailyAlerts]) error {
	var tenants []string
	err := db.WithSystemTx(ctx, w.d.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id FROM depguard_admin_tenants() WHERE disabled_at IS NULL`)
		if err != nil {
			return err
		}
		tenants, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		return err
	}
	day := time.Now().UTC().Format("2006-01-02")
	for _, t := range tenants {
		if err := w.d.enqueue(ctx, jobs.TenantDaily{TenantID: t}, &river.InsertOpts{MaxAttempts: 3,
			UniqueOpts: river.UniqueOpts{ByArgs: true, ByPeriod: 20 * time.Hour}}); err != nil {
			return err
		}
	}
	w.d.Logger.Info("daily alerts queued", "tenants", len(tenants), "day", day)
	return nil
}

type tenantDailyWorker struct {
	river.WorkerDefaults[jobs.TenantDaily]
	d Deps
}

func (w *tenantDailyWorker) Work(ctx context.Context, job *river.Job[jobs.TenantDaily]) error {
	now := time.Now()
	t := job.Args.TenantID
	if err := w.d.sendAlert(ctx, t, func(tx pgx.Tx, ch alerts.Channels) (notify.Message, []alerts.Item, error) {
		return alerts.OverdueAlert(ctx, tx, ch, w.d.PublicURL, now)
	}); err != nil {
		return err
	}
	return w.d.sendAlert(ctx, t, func(tx pgx.Tx, ch alerts.Channels) (notify.Message, []alerts.Item, error) {
		return alerts.Digest(ctx, tx, ch, w.d.PublicURL, now)
	})
}

// AlertPeriodicJobs checks deadlines and digests every day at 08:00 UTC.
func AlertPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{river.NewPeriodicJob(dailyAt{hour: 8},
		func() (river.JobArgs, *river.InsertOpts) { return jobs.DailyAlerts{}, nil },
		&river.PeriodicJobOpts{ID: "daily_alerts"})}
}

// dailyAt is a river.PeriodicSchedule firing once a day at hour:00 UTC.
type dailyAt struct{ hour int }

func (s dailyAt) Next(t time.Time) time.Time {
	t = t.UTC()
	n := time.Date(t.Year(), t.Month(), t.Day(), s.hour, 0, 0, 0, time.UTC)
	if !n.After(t) {
		n = n.Add(24 * time.Hour)
	}
	return n
}
