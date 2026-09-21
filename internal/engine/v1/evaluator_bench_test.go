package v1

import (
	"os"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

// BenchmarkEvaluateFixtures measures the per-event cost over the small
// fixture set, where the numbers are stable enough to compare across
// commits.
func BenchmarkEvaluateFixtures(b *testing.B) {
	tax, err := sigma.LoadTaxonomy("testdata/taxonomy")
	if err != nil {
		b.Fatal(err)
	}
	rs, _, err := sigma.LoadRuleSet("testdata/rules", tax)
	if err != nil {
		b.Fatal(err)
	}
	benchEvaluate(b, rs)
}

// BenchmarkEvaluateCorpus is the number that means something: every rule the
// engine accepts from the real SigmaHQ corpus, walked for one event. v1 has
// no index and no prefilter by design, so this is a linear scan over the
// whole rule set and the cost per rule is the interesting figure.
func BenchmarkEvaluateCorpus(b *testing.B) {
	const dir = "../../../corpora/sigmahq/rules"
	if _, err := os.Stat(dir); err != nil {
		b.Skip("SigmaHQ corpus not vendored")
	}
	tax, err := sigma.LoadTaxonomy("../../../config/taxonomy")
	if err != nil {
		b.Fatal(err)
	}
	rs, _, err := sigma.LoadRuleSet(dir, tax)
	if err != nil {
		b.Fatal(err)
	}
	b.Logf("%d rules", len(rs.Rules))
	benchEvaluate(b, rs)
}

func benchEvaluate(b *testing.B, rs *sigma.RuleSet) {
	b.Helper()
	e := New(rs)
	ev := sysmonDump()
	buf := make([]event.Verdict, 0, len(rs.Rules))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = e.EvaluateInto(buf[:0], ev)
	}
	b.StopTimer()
	if len(buf) != len(rs.Rules) {
		b.Fatalf("got %d verdicts for %d rules", len(buf), len(rs.Rules))
	}
	// Verdicts per second is the figure the pipeline is sized against: one
	// event costs one verdict per enabled rule, always.
	b.ReportMetric(float64(b.N*len(rs.Rules))/b.Elapsed().Seconds(), "verdicts/s")
}
