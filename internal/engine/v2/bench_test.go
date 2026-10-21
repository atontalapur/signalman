package v2

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	v1 "github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

// The single-event benchmarks use the same Sysmon process creation event
// and the same rule sets as v1's, so the two are read side by side.

func BenchmarkEvaluateFixtures(b *testing.B) {
	benchEvaluate(b, v1Fixtures(b), []*event.Event{sysmonDump()})
}

func BenchmarkEvaluateCorpus(b *testing.B) {
	rs := corpusSource(b)
	b.Logf("%d rules", len(rs.Rules))
	benchEvaluate(b, rs, []*event.Event{sysmonDump()})
}

// BenchmarkEvaluateCorpusStream cycles through the generated stream the
// equivalence test uses: events aimed at every rule, so the prefilter and
// the gate admit far more than they do for one fixed event.
func BenchmarkEvaluateCorpusStream(b *testing.B) {
	rs := corpusSource(b)
	benchEvaluate(b, rs, genEvents(rs, 1, 2))
}

// BenchmarkV1CorpusStream is v1 over the same stream, measured here so the
// stream comparison has a baseline. v1 itself is not touched.
func BenchmarkV1CorpusStream(b *testing.B) {
	rs := corpusSource(b)
	evs := genEvents(rs, 1, 2)
	e := v1.New(rs)
	buf := make([]event.Verdict, 0, len(rs.Rules))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = e.EvaluateInto(buf[:0], evs[i%len(evs)])
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/s")
}

// BenchmarkEvaluateCorpusParallel is throughput across every core, one
// evaluator shared by all goroutines the way the pipeline's workers will
// share it.
func BenchmarkEvaluateCorpusParallel(b *testing.B) {
	rs := corpusSource(b)
	evs := genEvents(rs, 1, 2)
	e := New(rs)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]event.Verdict, 0, len(rs.Rules))
		i := 0
		for pb.Next() {
			buf = e.EvaluateInto(buf[:0], evs[i%len(evs)])
			i++
		}
	})
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/s")
}

func benchEvaluate(b *testing.B, rs *sigma.RuleSet, evs []*event.Event) {
	b.Helper()
	e := New(rs)
	buf := make([]event.Verdict, 0, len(rs.Rules))
	for _, ev := range evs {
		buf = e.EvaluateInto(buf[:0], ev) // grow the scratch first
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = e.EvaluateInto(buf[:0], evs[i%len(evs)])
	}
	b.StopTimer()
	if len(buf) != len(rs.Rules) {
		b.Fatalf("got %d verdicts for %d rules", len(buf), len(rs.Rules))
	}
	b.ReportMetric(float64(b.N*len(rs.Rules))/b.Elapsed().Seconds(), "verdicts/s")
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "events/s")
}

// largestCorpus is every live SigmaHQ tree the engine accepts, merged: the
// largest rule set available here. A rule id seen in two trees keeps its
// first file, as LoadRuleSet does within one tree.
func largestCorpus(t testing.TB) *sigma.RuleSet {
	t.Helper()
	if _, err := corpusDir(); err != nil {
		t.Skip("SigmaHQ corpus not vendored")
	}
	tax, err := sigma.LoadTaxonomy("../../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	merged := &sigma.RuleSet{TaxonomyV: tax.Version, Version: "merged"}
	seen := map[string]bool{}
	for _, tree := range []string{"rules", "rules-emerging-threats", "rules-threat-hunting", "rules-compliance"} {
		dir := filepath.Join(corpusRoot(), tree)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		rs, _, err := sigma.LoadRuleSet(dir, tax)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs.Rules {
			if !seen[r.ID] {
				seen[r.ID] = true
				merged.Rules = append(merged.Rules, r)
			}
		}
	}
	sort.Slice(merged.Rules, func(i, j int) bool { return merged.Rules[i].ID < merged.Rules[j].ID })
	return merged
}

func BenchmarkCompileLargest(b *testing.B) {
	rs := largestCorpus(b)
	b.Logf("%d rules", len(rs.Rules))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(rs); err != nil {
			b.Fatal(err)
		}
	}
}

// TestCompileLargestRuleSet reports the compile time and program shape for
// the largest rule set, and holds the spec's two second budget.
func TestCompileLargestRuleSet(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus is not a short test")
	}
	rs := largestCorpus(t)
	start := time.Now()
	p, err := Compile(rs)
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	t.Logf("compiled %d rules in %v: %d leaves interned to %d predicates over %d fields, %d literals, Always %d",
		len(rs.Rules), took, p.Leaves(), len(p.Preds), len(p.fields), len(p.lits), p.AlwaysSize())
	if !raceEnabled && took > 2*time.Second {
		t.Fatalf("compile took %v, over the 2s budget", took)
	}
	// The merged set is also an equivalence check on rules the `rules`
	// tree does not have.
	res := compareEngines(t, rs, genEvents(rs, 1, 12))
	t.Logf("largest: %d rules, %d events, %d verdicts, %d matched, digests %v",
		res.rules, res.events, res.verdicts, res.matched, res.digests)
}

// TestCorpusLatency reports single-goroutine per-event latency over the
// generated stream. It measures, it does not gate: the spec's p99 target
// is for the reference machine. Run with SIGNALMAN_LATENCY=1.
func TestCorpusLatency(t *testing.T) {
	if os.Getenv("SIGNALMAN_LATENCY") == "" {
		t.Skip("set SIGNALMAN_LATENCY=1 to measure")
	}
	rs := corpusSource(t)
	evs := genEvents(rs, 4, 13)
	for _, eng := range []struct {
		name string
		f    func([]event.Verdict, *event.Event) []event.Verdict
	}{
		{"v2", New(rs).EvaluateInto},
		{"v1", v1.New(rs).EvaluateInto},
	} {
		buf := make([]event.Verdict, 0, len(rs.Rules))
		for _, ev := range evs {
			buf = eng.f(buf[:0], ev)
		}
		lat := make([]time.Duration, 0, len(evs))
		for _, ev := range evs {
			start := time.Now()
			buf = eng.f(buf[:0], ev)
			lat = append(lat, time.Since(start))
		}
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		q := func(p float64) time.Duration { return lat[int(p*float64(len(lat)-1))] }
		t.Logf("%s: %d rules, %d events: p50 %v p90 %v p99 %v max %v",
			eng.name, len(rs.Rules), len(lat), q(0.50), q(0.90), q(0.99), lat[len(lat)-1])
	}
}
