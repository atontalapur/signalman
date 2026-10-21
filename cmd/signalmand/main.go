// Command signalmand is the pipeline daemon: it consumes events.raw from
// Redpanda, normalizes each record through the taxonomy, evaluates it with
// the v1 engine, and writes events.norm, verdicts.v1, alerts, and drops. An
// in-process audit checks invariant 1 against those topics as offsets are
// committed.
//
// SIGHUP reloads the rule directory. The new rule set applies from the next
// batch on; a batch in flight finishes under the rules it started with. A
// taxonomy change needs a restart, because the normalizer is built from it.
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
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/atontalapur/signalman/internal/sigma"
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
	brokers          string
	group            string
	taxonomy         string
	rules            string
	strict           bool
	normalizeWorkers int
	matchWorkers     int
	queue            int
	inflight         int
	maxPoll          int
	metricsAddr      string
	createTopics     bool
	partitions       int
	auditInterval    time.Duration
	auditWindow      int64
	ruleEvalEvery    int
}

func parseFlags(args []string) (flags, error) {
	var f flags
	fs := flag.NewFlagSet("signalmand", flag.ContinueOnError)
	fs.StringVar(&f.brokers, "brokers", "localhost:19092", "comma-separated Kafka bootstrap brokers")
	fs.StringVar(&f.group, "group", "signalmand", "events.raw consumer group")
	fs.StringVar(&f.taxonomy, "taxonomy", "config/taxonomy", "taxonomy directory")
	fs.StringVar(&f.rules, "rules", "", "rule directory (required)")
	fs.BoolVar(&f.strict, "strict", true, "refuse to start or reload if any rule is rejected")
	// Fixed defaults, not runtime.GOMAXPROCS: the spec sizes pools at the
	// core count of the target node and requires them to be configured, so a
	// load test result is reproducible from its flags.
	fs.IntVar(&f.normalizeWorkers, "normalize-workers", 8, "normalize worker pool size")
	fs.IntVar(&f.matchWorkers, "match-workers", 8, "match worker pool size")
	fs.IntVar(&f.queue, "queue", 1024, "capacity of each stage channel")
	fs.IntVar(&f.inflight, "inflight", 4, "polled batches allowed to wait for the sink")
	fs.IntVar(&f.maxPoll, "max-poll", 500, "records per poll, which is the batch size")
	fs.StringVar(&f.metricsAddr, "metrics-addr", ":9464", "address serving /metrics")
	fs.BoolVar(&f.createTopics, "create-topics", false, "create missing pipeline topics at startup")
	fs.IntVar(&f.partitions, "partitions", 8, "partitions per topic for -create-topics")
	fs.DurationVar(&f.auditInterval, "audit-interval", 10*time.Second, "how often the invariant 1 audit runs; 0 disables it")
	fs.Int64Var(&f.auditWindow, "audit-window", 10000, "widest seq range the audit checks at once")
	fs.IntVar(&f.ruleEvalEvery, "rule-eval-every", 100, "time every rule on events whose seq is a multiple of this, for signalman_rule_eval_seconds; 0 disables")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if f.rules == "" {
		return f, errors.New("-rules is required")
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
		fmt.Fprintln(os.Stderr, "signalmand:", err)
		os.Exit(2)
	}
	if err := run(f, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("signalmand stopped", "err", err)
		os.Exit(1)
	}
}

// loadRules loads the rule set and reports every rejection. Under -strict
// any rejection is an error, because a rule that silently fails to load is
// a missed detection with nothing to show for it.
func loadRules(dir string, tax *sigma.Taxonomy, strict bool, log *slog.Logger) (*sigma.RuleSet, error) {
	rs, errs, err := sigma.LoadRuleSet(dir, tax)
	if err != nil {
		return nil, err
	}
	for _, e := range errs {
		log.Error("rule rejected", "path", e.Path, "rule_id", e.RuleID, "code", e.Code, "line", e.Line, "reason", e.Reason)
	}
	if strict && len(errs) > 0 {
		return nil, fmt.Errorf("%d rules rejected under -strict", len(errs))
	}
	if len(rs.Rules) == 0 {
		return nil, fmt.Errorf("no rules loaded from %s", dir)
	}
	log.Info("rule set loaded", "rules", len(rs.Rules), "rejected", len(errs), "ruleset_v", rs.Version, "taxonomy_v", rs.TaxonomyV)
	return rs, nil
}

func run(f flags, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tax, err := sigma.LoadTaxonomy(f.taxonomy)
	if err != nil {
		return err
	}
	rs, err := loadRules(f.rules, tax, f.strict, log)
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := obs.New(reg)
	srv := &http.Server{Addr: f.metricsAddr, Handler: metricsMux(reg), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics server", "err", err)
		}
	}()
	defer func() { _ = srv.Close() }()

	b, err := kafka.Dial(ctx, kafka.Config{
		Brokers:        strings.Split(f.brokers, ","),
		ClientID:       "signalmand",
		MaxPollRecords: f.maxPoll,
	})
	if err != nil {
		return err
	}
	defer b.Close()
	if f.createTopics {
		if err := b.EnsureTopics(ctx, topicSpecs(int32(f.partitions))); err != nil {
			return err
		}
	}

	slot := pipe.NewSlot(pipe.V1(rs), m)
	go reloadOnHUP(ctx, f, tax, slot, log)

	// The audit snapshots its starting point before the pipeline produces
	// anything, so it must be built first.
	if f.auditInterval > 0 {
		a, err := pipe.NewAuditor(ctx, b, pipe.AuditConfig{Group: f.group, Window: f.auditWindow}, slot.RuleCount, m, log)
		if err != nil {
			return err
		}
		defer a.Close()
		go a.Run(ctx, f.auditInterval)
	}

	p, err := pipe.New(pipe.Config{
		Group:              f.group,
		NormalizeWorkers:   f.normalizeWorkers,
		MatchWorkers:       f.matchWorkers,
		QueueSize:          f.queue,
		MaxInflightBatches: f.inflight,
		RuleEvalEvery:      f.ruleEvalEvery,
	}, b, pipe.NewNormalizer(tax, pipe.NormalizeConfig{}, m), slot, m, log)
	if err != nil {
		return err
	}
	log.Info("signalmand started", "version", version, "commit", commit, "brokers", f.brokers, "group", f.group)
	return p.Run(ctx)
}

func metricsMux(reg *prometheus.Registry) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return mux
}

func reloadOnHUP(ctx context.Context, f flags, tax *sigma.Taxonomy, slot *pipe.Slot, log *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			rs, err := loadRules(f.rules, tax, f.strict, log)
			if err != nil {
				log.Error("reload refused; keeping the active rule set", "err", err)
				continue
			}
			slot.Store(pipe.V1(rs))
			log.Info("rule set reloaded; applies from the next batch", "ruleset_v", rs.Version)
		}
	}
}

// topicSpecs mirrors deploy/docker-compose.yml.
func topicSpecs(partitions int32) []kafka.TopicSpec {
	week, month := "604800000", "2592000000"
	specs := []kafka.TopicSpec{
		{Name: pipe.TopicEventsRaw},
		{Name: pipe.TopicEventsNorm},
		{Name: pipe.TopicAlerts},
		{Name: pipe.TopicVerdictsV1, Configs: map[string]string{"retention.ms": week}},
		{Name: pipe.TopicDrops, Configs: map[string]string{"retention.ms": month}},
	}
	for i := range specs {
		specs[i].Partitions, specs[i].Replication = partitions, 1
	}
	return specs
}
