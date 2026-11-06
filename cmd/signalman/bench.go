package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/fixture"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// cmdBench times each rule's condition walk and flags any rule whose p99 is
// over the latency budget, 50 microseconds by default. Over budget usually
// means an unanchored regex that should have been a contains.
//
// Each sample is one ast.Eval of the rule's bound tree on one event, the
// events taken round robin. The logsource test is deliberately not applied:
// a rule is measured on every event, including ones its logsource would
// skip, so the figure is the cost of the tree itself. Events come from
// --corpus when given, otherwise from the fixtures of the rules named.
func cmdBench(args []string, stdout, stderr io.Writer) int {
	fs, taxDir := newFlags("bench", stderr)
	corpus := fs.String("corpus", "", "directory of .ndjson or .jsonl events to time against (default: the rules' fixtures)")
	samples := fs.Int("samples", 10000, "timed evaluations per rule")
	threshold := fs.Duration("threshold", 50*time.Microsecond, "p99 latency budget per rule")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	if *samples < 1 {
		fmt.Fprintln(stderr, "signalman: --samples must be at least 1")
		return exitUsage
	}
	tax, ok := loadTaxonomy(*taxDir, stderr)
	if !ok {
		return exitUsage
	}
	paths, ok := ruleFiles(pos, stderr)
	if !ok {
		return exitUsage
	}
	rs, errs := sigma.LoadRuleFiles(paths, tax)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(stdout, e.Error())
		}
		return exitFail
	}

	events, err := benchEvents(*corpus, paths)
	if err != nil {
		fmt.Fprintf(stderr, "signalman: %v\n", err)
		return exitUsage
	}
	if len(events) == 0 {
		fmt.Fprintln(stderr, "signalman: no events to time against: give --corpus or add fixtures")
		return exitUsage
	}

	// Report in path order, which is the order the author named them in
	// after sorting, rather than rule id order.
	rules := make([]*sigma.Rule, len(rs.Rules))
	for i := range rs.Rules {
		rules[i] = &rs.Rules[i]
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Path < rules[j].Path })

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "rule\tp50\tp99\tmax\tsamples")
	slow := 0
	for _, r := range rules {
		st := timeRule(r, events, *samples)
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%d", r.Path, st.p50, st.p99, st.max, *samples)
		if st.p99 > *threshold {
			slow++
			row += "\tSLOW"
		}
		fmt.Fprintln(tw, row)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "signalman: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stdout, "%d rules, %d over the %s p99 budget, %d events\n", len(rules), slow, *threshold, len(events))
	if slow > 0 {
		return exitFail
	}
	return exitOK
}

func benchEvents(corpus string, paths []string) ([]*event.Event, error) {
	var out []*event.Event
	if corpus != "" {
		evs, err := readCorpus(corpus)
		if err != nil {
			return nil, err
		}
		for _, e := range evs {
			out = append(out, e.Event)
		}
		return out, nil
	}
	for _, p := range paths {
		fp := sigma.FixturePath(p)
		if _, err := os.Stat(fp); err != nil {
			continue
		}
		f, err := fixture.Load(fp)
		if err != nil {
			return nil, err
		}
		for _, c := range f.Cases {
			out = append(out, c.Event)
		}
	}
	return out, nil
}

type latency struct{ p50, p99, max time.Duration }

// The result of each evaluation is discarded. ast.Eval is recursive, so it
// is never inlined, and the compiler does not drop a call it has not
// inlined.
func timeRule(r *sigma.Rule, events []*event.Event, samples int) latency {
	// One untimed pass, so first-touch costs are not charged to the
	// first few samples.
	for _, ev := range events {
		ast.Eval(r.Cond, ev)
	}
	d := make([]time.Duration, samples)
	for i := range d {
		ev := events[i%len(events)]
		start := time.Now()
		ast.Eval(r.Cond, ev)
		d[i] = time.Since(start)
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return latency{p50: quantile(d, 0.50), p99: quantile(d, 0.99), max: d[len(d)-1]}
}

// quantile is the nearest-rank quantile of sorted durations.
func quantile(sorted []time.Duration, q float64) time.Duration {
	i := int(math.Ceil(q*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}
