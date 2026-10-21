// Command differ is the shadow-mode verdict comparison. It joins
// verdicts.v1 and verdicts.v2 on (partition, seq, rule_id), classifies
// every disagreement into the spec's five classes, writes each one to the
// divergences topic, and logs it as one JSON line on stderr: the raw
// material for the divergence log in docs/cutover.md.
//
// It resumes from offsets committed under -group on both verdict topics.
// Run one instance per group: the join is per partition and an instance
// owns every partition.
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
	"github.com/atontalapur/signalman/internal/differ"
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
	brokers        string
	group          string
	queue          int
	maxPoll        int
	commitInterval time.Duration
	metricsAddr    string
}

func parseFlags(args []string) (flags, error) {
	var f flags
	fs := flag.NewFlagSet("differ", flag.ContinueOnError)
	fs.StringVar(&f.brokers, "brokers", "localhost:19092", "comma-separated Kafka bootstrap brokers")
	fs.StringVar(&f.group, "group", "differ", "group the differ's offsets are committed under")
	fs.IntVar(&f.queue, "queue", 256, "records one side may run ahead of the other, per partition")
	fs.IntVar(&f.maxPoll, "max-poll", 500, "records per poll")
	fs.DurationVar(&f.commitInterval, "commit-interval", time.Second, "how often offsets are committed")
	fs.StringVar(&f.metricsAddr, "metrics-addr", ":9465", "address serving /metrics")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if f.queue <= 0 || f.maxPoll <= 0 {
		return f, errors.New("-queue and -max-poll must be positive")
	}
	return f, nil
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	f, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "differ:", err)
		os.Exit(2)
	}
	if err := run(f, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("differ stopped", "err", err)
		os.Exit(1)
	}
}

func run(f flags, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := differ.NewMetrics(reg)
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
		ClientID:       "differ",
		MaxPollRecords: f.maxPoll,
	})
	if err != nil {
		return err
	}
	defer b.Close()
	d, err := differ.New(differ.Config{Group: f.group, Queue: f.queue, CommitInterval: f.commitInterval}, b, m, log)
	if err != nil {
		return err
	}
	log.Info("differ started", "version", version, "commit", commit, "brokers", f.brokers, "group", f.group)
	return d.Run(ctx)
}
