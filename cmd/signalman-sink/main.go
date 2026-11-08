// Command signalman-sink moves alerts from the alerts topic into the
// ClickHouse alerts table (deploy/clickhouse/001_alerts.sql). It commits an
// offset only after the rows before it are inserted, so delivery is
// at-least-once and redeliveries collapse in the table's ReplacingMergeTree.
//
// With -lane events it instead moves events.norm into the events table
// (deploy/clickhouse/003_events.sql) that signalman hunt retro-hunts over.
// Run one process per lane, so a slow events table never holds alerts back.
//
// It is its own process, not a stage of signalmand, so that a ClickHouse
// outage stops alert storage and nothing else: signalmand keeps producing
// verdicts and alerts into Redpanda, and the backlog shows up as this
// group's consumer lag on alerts until ClickHouse returns.
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
	"strings"
	"syscall"
	"time"

	"github.com/atontalapur/signalman/internal/backend/ch"
	"github.com/atontalapur/signalman/internal/broker/kafka"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe/chsink"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Set by GoReleaser.
var (
	version = "dev"
	commit  = ""
)

type flags struct {
	lane          string
	brokers       string
	group         string
	clickhouse    string
	table         string
	batchRows     int
	flushInterval time.Duration
	maxPoll       int
	metricsAddr   string
}

func parseFlags(args []string) (flags, error) {
	var f flags
	fs := flag.NewFlagSet("signalman-sink", flag.ContinueOnError)
	fs.StringVar(&f.lane, "lane", "alerts", "what to store: alerts (alerts topic) or events (events.norm)")
	fs.StringVar(&f.brokers, "brokers", "localhost:19092", "comma-separated Kafka bootstrap brokers")
	fs.StringVar(&f.group, "group", "", "consumer group (default signalman-sink, or signalman-events for -lane events)")
	fs.StringVar(&f.clickhouse, "clickhouse", ch.ComposeDSN, "clickhouse-go DSN")
	fs.StringVar(&f.table, "table", "", "table to insert into (default alerts, or events for -lane events)")
	// ClickHouse writes a part per insert and wants few, large inserts.
	fs.IntVar(&f.batchRows, "batch-rows", 5000, "insert once this many rows are buffered")
	fs.DurationVar(&f.flushInterval, "flush-interval", time.Second, "insert a partial batch this long after its first row")
	fs.IntVar(&f.maxPoll, "max-poll", 500, "records per poll")
	fs.StringVar(&f.metricsAddr, "metrics-addr", "", "address serving /metrics (default :9465, or :9467 for -lane events)")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	var errs []error
	def, ok := laneDefaults[f.lane]
	if !ok {
		errs = append(errs, fmt.Errorf("-lane %q is not alerts or events", f.lane))
	}
	if f.group == "" {
		f.group = def.group
	}
	if f.table == "" {
		f.table = def.table
	}
	if f.metricsAddr == "" {
		f.metricsAddr = def.metricsAddr
	}
	if f.clickhouse == "" {
		errs = append(errs, errors.New("-clickhouse is required"))
	}
	if f.batchRows <= 0 || f.maxPoll <= 0 {
		errs = append(errs, errors.New("-batch-rows and -max-poll must be positive"))
	}
	if f.flushInterval <= 0 {
		errs = append(errs, errors.New("-flush-interval must be positive"))
	}
	return f, errors.Join(errs...)
}

// laneDefaults are the per-lane defaults. signalmand serves :9464 and the
// differ :9466.
var laneDefaults = map[string]struct{ group, table, metricsAddr, clientID string }{
	"alerts": {"signalman-sink", "alerts", ":9465", "signalman-sink"},
	"events": {"signalman-events", "events", ":9467", "signalman-sink-events"},
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	f, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "signalman-sink:", err)
		os.Exit(2)
	}
	if err := run(f, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("signalman-sink stopped", "err", err)
		os.Exit(1)
	}
}

func run(f flags, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := obs.New(reg)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: f.metricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server", "err", err)
		}
	}()
	defer func() { _ = srv.Close() }()

	b, err := kafka.Dial(ctx, kafka.Config{
		Brokers:        strings.Split(f.brokers, ","),
		ClientID:       laneDefaults[f.lane].clientID,
		MaxPollRecords: f.maxPoll,
	})
	if err != nil {
		return err
	}
	defer b.Close()

	cfg := chsink.Config{
		Group:         f.group,
		BatchRows:     f.batchRows,
		FlushInterval: f.flushInterval,
	}
	// ClickHouse must answer at startup, so a wrong DSN fails fast. Once
	// running, an outage is retried, not fatal.
	var lane interface{ Run(context.Context) error }
	if f.lane == "events" {
		tbl, err := chsink.OpenEvents(ctx, f.clickhouse, f.table)
		if err != nil {
			return err
		}
		defer func() { _ = tbl.Close() }()
		if lane, err = chsink.NewEvents(cfg, b, tbl, m, log); err != nil {
			return err
		}
	} else {
		tbl, err := chsink.Open(ctx, f.clickhouse, f.table)
		if err != nil {
			return err
		}
		defer func() { _ = tbl.Close() }()
		if lane, err = chsink.New(cfg, b, tbl, m, log); err != nil {
			return err
		}
	}
	log.Info("signalman-sink started", "version", version, "commit", commit, "lane", f.lane, "brokers", f.brokers, "group", f.group, "table", f.table)
	return lane.Run(ctx)
}
