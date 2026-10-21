// Command loadgen replays a corpus into events.raw at a multiple of a
// measured baseline rate, for the Plan F load experiments.
//
// The corpus is either a directory of .ndjson/.jsonl events (-corpus) or
// events generated from a rule directory (-rules), aimed at the rules the
// way the v2 equivalence harness aims them, so true verdicts are common.
// The rate is -multiple times -baseline, or a -profile of several phases.
// -measure-baseline runs the pipeline in process over the in-memory broker
// first and uses its measured throughput as the baseline.
//
//	loadgen -rules rules -baseline 2000 -multiple 2 -duration 30m
//	loadgen -rules rules -measure-baseline 20000 -profile 2:30m,0:10m
//	loadgen -corpus corpora/events -baseline 2000 -profile 1:5m,5:1m,1:5m
//
// The schedule is fixed by the corpus and the profile; only timing varies
// between runs. The generator holds one batch at a time and never skips a
// record: a broker slower than the profile shows as lateness in the final
// report, not as a buffer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/broker/kafka"
	"github.com/atontalapur/signalman/internal/loadtest"
	"github.com/atontalapur/signalman/internal/sigma"
)

type flags struct {
	brokers         string
	corpus          string
	rules           string
	taxonomy        string
	source          string
	perRule         int
	seed            int64
	baseline        float64
	measureBaseline int
	multiple        float64
	duration        time.Duration
	profile         string
	batch           int
}

func parseFlags(args []string, stderr io.Writer) (flags, error) {
	var f flags
	fs := flag.NewFlagSet("loadgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&f.brokers, "brokers", "localhost:19092", "comma-separated Kafka bootstrap brokers")
	fs.StringVar(&f.corpus, "corpus", "", "directory of .ndjson/.jsonl events to replay")
	fs.StringVar(&f.rules, "rules", "", "rule directory to generate events from (instead of -corpus)")
	fs.StringVar(&f.taxonomy, "taxonomy", "config/taxonomy", "taxonomy directory")
	fs.StringVar(&f.source, "source", "sysmon", "source header for -corpus lines without a source field")
	fs.IntVar(&f.perRule, "per-rule", 20, "generated events per rule (-rules)")
	fs.Int64Var(&f.seed, "seed", 1, "generator seed (-rules)")
	fs.Float64Var(&f.baseline, "baseline", 0, "baseline rate in events/s that -multiple and -profile scale")
	fs.IntVar(&f.measureBaseline, "measure-baseline", 0, "measure the baseline in process over this many events first (needs -rules)")
	fs.Float64Var(&f.multiple, "multiple", 1, "rate as a multiple of the baseline")
	fs.DurationVar(&f.duration, "duration", time.Minute, "how long to replay at -multiple")
	fs.StringVar(&f.profile, "profile", "", "phases as multiple:duration,... (overrides -multiple and -duration)")
	fs.IntVar(&f.batch, "batch", 100, "records per produce call")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if (f.corpus == "") == (f.rules == "") {
		return f, errors.New("exactly one of -corpus and -rules is required")
	}
	if f.measureBaseline > 0 && f.rules == "" {
		return f, errors.New("-measure-baseline needs -rules: the in-process pipeline evaluates them")
	}
	if f.baseline <= 0 && f.measureBaseline <= 0 {
		return f, errors.New("a baseline is required: -baseline or -measure-baseline")
	}
	return f, nil
}

// parseProfile turns "2:30m,0:10m" into phases at multiples of base.
func parseProfile(s string, base float64) ([]loadtest.Phase, error) {
	var out []loadtest.Phase
	for part := range strings.SplitSeq(s, ",") {
		m, d, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok {
			return nil, fmt.Errorf("profile phase %q: want multiple:duration", part)
		}
		x, err := strconv.ParseFloat(m, 64)
		if err != nil || x < 0 {
			return nil, fmt.Errorf("profile phase %q: bad multiple", part)
		}
		dur, err := time.ParseDuration(d)
		if err != nil || dur <= 0 {
			return nil, fmt.Errorf("profile phase %q: bad duration", part)
		}
		out = append(out, loadtest.Phase{Rate: x * base, For: dur})
	}
	if len(out) == 0 {
		return nil, errors.New("empty profile")
	}
	return out, nil
}

func main() {
	f, err := parseFlags(os.Args[1:], os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dial := func(ctx context.Context) (broker.Broker, error) {
		return kafka.Dial(ctx, kafka.Config{Brokers: strings.Split(f.brokers, ","), ClientID: "loadgen"})
	}
	if err := run(ctx, f, dial, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, f flags, dial func(context.Context) (broker.Broker, error), out io.Writer) error {
	tax, err := sigma.LoadTaxonomy(f.taxonomy)
	if err != nil {
		return err
	}
	var (
		c  *loadtest.Corpus
		rs *sigma.RuleSet
	)
	if f.rules != "" {
		var errs []sigma.LoadError
		rs, errs, err = sigma.LoadRuleSet(f.rules, tax)
		if err != nil {
			return err
		}
		if len(rs.Rules) == 0 {
			return fmt.Errorf("no rules loaded from %s", f.rules)
		}
		c, err = loadtest.FromRules(rs, tax, f.perRule, f.seed)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "corpus: %d records generated from %d rules (%d rejected rules, %d records excluded as drops)\n",
			len(c.Records), len(rs.Rules), len(errs), c.Excluded)
	} else {
		c, err = loadtest.ReadNDJSON(f.corpus, f.source)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "corpus: %d records from %s, %d will be dropped by the normalizer\n", len(c.Records), f.corpus, c.Drops(tax))
	}

	base := f.baseline
	if f.measureBaseline > 0 {
		capy, err := loadtest.MeasureCapacity(ctx, loadtest.Config{Rules: rs, Taxonomy: tax}, c, f.measureBaseline, time.Hour)
		if err != nil {
			return err
		}
		base = capy.Rate
		fmt.Fprintf(out, "baseline: %.0f events/s in process, in-memory broker (%d events in %v, steady %.0f/s)\n",
			capy.Rate, capy.Events, capy.Elapsed.Round(time.Millisecond), capy.Steady)
	}
	phases := []loadtest.Phase{{Rate: f.multiple * base, For: f.duration}}
	if f.profile != "" {
		if phases, err = parseProfile(f.profile, base); err != nil {
			return err
		}
	}
	total := 0
	for _, p := range phases {
		total += p.Count()
		fmt.Fprintf(out, "phase: %.0f events/s for %v (%.2fx)\n", p.Rate, p.For, p.Rate/base)
	}

	b, err := dial(ctx)
	if err != nil {
		return err
	}
	defer b.Close()
	st, err := loadtest.Replay(ctx, b, c, loadtest.ReplayConfig{Phases: phases, Batch: f.batch})
	fmt.Fprintf(out, "sent %d of %d records in %v (%.0f/s offered), %d batches, %d retries, at most %v behind schedule\n",
		st.Sent, total, st.Elapsed.Round(time.Millisecond), st.Offered(), st.Batches, st.Retries, st.MaxBehind.Round(time.Millisecond))
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
