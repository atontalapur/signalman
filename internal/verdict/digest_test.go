package verdict

import (
	"math/rand"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func verdicts(seqs []uint64, ruleIDs []string, matched func(uint64, string) bool) []event.Verdict {
	var out []event.Verdict
	for _, s := range seqs {
		for _, id := range ruleIDs {
			out = append(out, event.Verdict{
				Seq:     s,
				RuleID:  id,
				Matched: matched(s, id),
				Engine:  "v1",
			})
		}
	}
	return out
}

func alternating(seq uint64, ruleID string) bool { return (seq+uint64(len(ruleID)))%2 == 0 }

func foldAll(t *testing.T, vs []event.Verdict) string {
	t.Helper()
	d := New()
	for _, v := range vs {
		if err := d.Fold(v); err != nil {
			t.Fatalf("fold %+v: %v", v, err)
		}
	}
	return d.Sum()
}

func TestDigestIsStableForTheSameStream(t *testing.T) {
	vs := verdicts([]uint64{1, 2, 3}, []string{"a", "b"}, alternating)
	first := foldAll(t, vs)
	for i := 0; i < 10; i++ {
		if got := foldAll(t, vs); got != first {
			t.Fatalf("run %d = %s, want %s", i, got, first)
		}
	}
	if first == "" {
		t.Fatal("a digest over a non-empty stream must not be empty")
	}
}

func TestDigestIsIndependentOfRuleOrderWithinASeq(t *testing.T) {
	// The gate for Plan B: same corpus, rule set shuffled ten times,
	// identical digest. Rules are folded per event, so the digest may not
	// depend on the order they arrive in.
	ids := []string{"r1", "r2", "r3", "r4", "r5"}
	want := foldAll(t, verdicts([]uint64{1, 2, 3}, ids, alternating))

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 10; i++ {
		shuffled := make([]string, len(ids))
		copy(shuffled, ids)
		rng.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})
		if got := foldAll(t, verdicts([]uint64{1, 2, 3}, shuffled, alternating)); got != want {
			t.Fatalf("shuffle %d (%v) = %s, want %s", i, shuffled, got, want)
		}
	}
}

func TestDigestBindsAVerdictToItsEvent(t *testing.T) {
	// Events are an ordered stream within a partition, and the digest is a
	// statement about that stream. The same multiset of verdicts attached
	// to different events is a different stream, so it must not collide.
	a := foldAll(t, []event.Verdict{
		{Seq: 1, RuleID: "r", Matched: true},
		{Seq: 2, RuleID: "r", Matched: false},
	})
	b := foldAll(t, []event.Verdict{
		{Seq: 1, RuleID: "r", Matched: false},
		{Seq: 2, RuleID: "r", Matched: true},
	})
	if a == b {
		t.Fatal("swapping which event matched must change the digest")
	}
}

func TestDigestGapsInSeqAreNotTheSameAsNoGap(t *testing.T) {
	// A partition can skip sequence numbers when events are dropped to the
	// ledger, and a digest that ignored the numbers themselves would call
	// a lossy stream equal to a complete one.
	a := foldAll(t, []event.Verdict{
		{Seq: 1, RuleID: "r", Matched: true},
		{Seq: 2, RuleID: "r", Matched: true},
	})
	b := foldAll(t, []event.Verdict{
		{Seq: 1, RuleID: "r", Matched: true},
		{Seq: 9, RuleID: "r", Matched: true},
	})
	if a == b {
		t.Fatal("the seq values are folded, not just their order")
	}
}

func TestDigestChangesWithEveryFoldedField(t *testing.T) {
	base := event.Verdict{Seq: 1, RuleID: "r", Matched: true}
	cases := map[string]event.Verdict{
		"seq":     {Seq: 2, RuleID: "r", Matched: true},
		"rule id": {Seq: 1, RuleID: "s", Matched: true},
		"matched": {Seq: 1, RuleID: "r", Matched: false},
	}
	want := foldAll(t, []event.Verdict{base})
	for name, v := range cases {
		if got := foldAll(t, []event.Verdict{v}); got == want {
			t.Errorf("changing the %s did not change the digest", name)
		}
	}
}

func TestDigestIgnoresFieldsThatAreNotTheVerdict(t *testing.T) {
	// Engine, versions, and partition identify the stream, not the verdict.
	// They are compared separately; folding them in would make two engines
	// differ by construction and the comparison meaningless.
	a := foldAll(t, []event.Verdict{{
		Seq: 1, RuleID: "r", Matched: true,
		Engine: "v1", RuleSetV: "aaa", TaxonomyV: "bbb", Partition: 3,
	}})
	b := foldAll(t, []event.Verdict{{
		Seq: 1, RuleID: "r", Matched: true,
		Engine: "v2", RuleSetV: "ccc", TaxonomyV: "ddd", Partition: 9,
	}})
	if a != b {
		t.Fatal("the digest folds the verdict, not the stream identity")
	}
}

func TestDigestRejectsAnOutOfOrderSeq(t *testing.T) {
	// A digest over a partition assumes monotonic seq. Silently folding a
	// regression would produce a digest that means nothing, so it is an
	// error the caller has to see.
	d := New()
	if err := d.Fold(event.Verdict{Seq: 5, RuleID: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Fold(event.Verdict{Seq: 5, RuleID: "s"}); err != nil {
		t.Fatalf("another rule at the same seq is the normal case: %v", err)
	}
	if err := d.Fold(event.Verdict{Seq: 4, RuleID: "r"}); err == nil {
		t.Fatal("a seq going backwards must be an error")
	}
}

func TestDigestOfNothingIsStableAndDistinct(t *testing.T) {
	empty := New().Sum()
	if empty == "" {
		t.Fatal("an empty digest must still be a value")
	}
	if empty == foldAll(t, []event.Verdict{{Seq: 1, RuleID: "r", Matched: false}}) {
		t.Fatal("an empty stream and a one-false-verdict stream are different")
	}
}

func TestDigestCountsWhatItFolded(t *testing.T) {
	d := New()
	for _, v := range verdicts([]uint64{1, 2}, []string{"a", "b"}, alternating) {
		if err := d.Fold(v); err != nil {
			t.Fatal(err)
		}
	}
	if d.Verdicts() != 4 {
		t.Fatalf("folded %d verdicts, want 4", d.Verdicts())
	}
	if d.Events() != 2 {
		t.Fatalf("saw %d distinct seqs, want 2", d.Events())
	}
}

func TestSetFoldsPerPartitionIndependently(t *testing.T) {
	// Partitions are independent ordered streams, so each carries its own
	// digest. A set is how two engines are compared across a whole topic.
	s := NewSet()
	for _, v := range []event.Verdict{
		{Seq: 1, Partition: 0, RuleID: "r", Matched: true},
		{Seq: 1, Partition: 1, RuleID: "r", Matched: false},
		{Seq: 2, Partition: 0, RuleID: "r", Matched: false},
	} {
		if err := s.Fold(v); err != nil {
			t.Fatal(err)
		}
	}
	sums := s.Sums()
	if len(sums) != 2 {
		t.Fatalf("got %d partitions, want 2", len(sums))
	}
	if sums[0] == sums[1] {
		t.Fatal("two partitions carrying different verdicts must differ")
	}

	// A partition's digest must not depend on the other partition's
	// traffic, or a shard rebalance would look like a divergence.
	alone := New()
	for _, v := range []event.Verdict{
		{Seq: 1, Partition: 0, RuleID: "r", Matched: true},
		{Seq: 2, Partition: 0, RuleID: "r", Matched: false},
	} {
		if err := alone.Fold(v); err != nil {
			t.Fatal(err)
		}
	}
	if sums[0] != alone.Sum() {
		t.Fatal("interleaved partitions must fold as if each ran alone")
	}
}

func TestSetSumsAreSortedByPartition(t *testing.T) {
	s := NewSet()
	for _, p := range []int32{5, 1, 3} {
		if err := s.Fold(event.Verdict{Seq: 1, Partition: p, RuleID: "r"}); err != nil {
			t.Fatal(err)
		}
	}
	parts := s.Partitions()
	if len(parts) != 3 || parts[0] != 1 || parts[1] != 3 || parts[2] != 5 {
		t.Fatalf("partitions = %v, want sorted", parts)
	}
}
