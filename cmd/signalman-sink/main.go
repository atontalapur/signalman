// Command signalman-sink moves alerts from the alerts topic into the
// ClickHouse alerts table (deploy/clickhouse/001_alerts.sql). It commits an
// offset only after the rows before it are inserted, so delivery is
// at-least-once and redeliveries collapse in the table's ReplacingMergeTree.
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
	fs.StringVar(&f.brokers, "brokers", "localhost:19092", "comma-separated Kafka bootstrap brokers")
	fs.StringVar(&f.group, "group", "signalman-sink", "alerts consumer group")
	fs.StringVar(&f.clickhouse, "clickhouse", "clickhouse://signalman:signalman@localhost:9000/signalman", "clickhouse-go DSN")
	fs.StringVar(&f.table, "table", "alerts", "table to insert into")
	// ClickHouse writes a part per insert and wants few, large inserts.
	fs.IntVar(&f.batchRows, "batch-rows", 5000, "insert once this many rows are buffered")
	fs.DurationVar(&f.flushInterval, "flush-interval", time.Second, "insert a partial batch this long after its first row")
	fs.IntVar(&f.maxPoll, "max-poll", 500, "records per poll")
	fs.StringVar(&f.metricsAddr, "metrics-addr", ":9465", "address serving /metrics")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	var errs []error
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
		ClientID:       "signalman-sink",
		MaxPollRecords: f.maxPoll,
	})
	if err != nil {
		return err
	}
	defer b.Close()

	// ClickHouse must answer at startup, so a wrong DSN fails fast. Once
	// running, an outage is retried, not fatal.
	ch, err := chsink.Open(ctx, f.clickhouse, f.table)
	if err != nil {
		return err
	}
	defer func() { _ = ch.Close() }()

	s, err := chsink.New(chsink.Config{
		Group:         f.group,
		BatchRows:     f.batchRows,
		FlushInterval: f.flushInterval,
	}, b, ch, m, log)
	if err != nil {
		return err
	}
	log.Info("signalman-sink started", "version", version, "commit", commit, "brokers", f.brokers, "group", f.group, "table", f.table)
	return s.Run(ctx)
}
