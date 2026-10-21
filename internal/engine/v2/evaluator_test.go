package v2

import (
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

func sysmonDump() *event.Event {
	return &event.Event{
		Seq:       42,
		Partition: 7,
		Source:    "winlog",
		Fields: map[string]event.Value{
			"channel":     event.String("Microsoft-Windows-Sysmon/Operational"),
			"event_id":    event.Int(1),
			"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
			"CommandLine": event.String(`rundll32.exe comsvcs.dll, MiniDump 624 C:\t.dmp full`),
			"ParentImage": event.String(`C:\Windows\explorer.exe`),
		},
	}
}

func v1Fixtures(t testing.TB) *sigma.RuleSet {
	t.Helper()
	return loadSet(t, "../v1/testdata/rules", "../v1/testdata/taxonomy")
}

func TestEvaluateShape(t *testing.T) {
	rs := v1Fixtures(t)
	ev := sysmonDump()
	vs := New(rs).Evaluate(ev)
	if len(vs) != len(rs.Rules) {
		t.Fatalf("got %d verdicts for %d rules", len(vs), len(rs.Rules))
	}
	for i, v := range vs {
		if v.RuleID != rs.Rules[i].ID {
			t.Fatalf("verdict %d is rule %s, want %s (rule id order)", i, v.RuleID, rs.Rules[i].ID)
		}
		if v.Engine != "v2" || Name != "v2" {
			t.Fatalf("engine = %q", v.Engine)
		}
		if v.Seq != ev.Seq || v.Partition != ev.Partition || v.RuleSetV != rs.Version || v.TaxonomyV != rs.TaxonomyV {
			t.Fatalf("verdict does not carry the event and version identity: %+v", v)
		}
	}
	if !vs[0].Matched || vs[2].Matched {
		t.Fatalf("verdicts = %+v", vs)
	}
}

func TestEvaluateIntoAppends(t *testing.T) {
	rs := v1Fixtures(t)
	e := New(rs)
	buf := make([]event.Verdict, 1, 8)
	buf = e.EvaluateInto(buf, sysmonDump())
	if len(buf) != 1+len(rs.Rules) {
		t.Fatalf("EvaluateInto must append, got %d", len(buf))
	}
	if e.RuleSet() != rs {
		t.Fatal("RuleSet must return the rule set evaluated")
	}
}

// Two rules writing the same leaf must share one predicate; that sharing
// is the point of interning.
func TestPredicatesAreInterned(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../v1/testdata/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	src := func(id, extra string) sigma.Rule {
		y := `
title: t
id: ` + id + `
level: low
logsource: {product: windows, category: process_creation}
detection:
  sel:
    Image|endswith: '\rundll32.exe'
  other:
    CommandLine|contains: '` + extra + `'
  condition: sel and other
`
		r, lerr := sigma.LoadRuleBytes(id, []byte(y), tax)
		if lerr != nil {
			t.Fatal(lerr)
		}
		return *r
	}
	rs := &sigma.RuleSet{
		Rules:     []sigma.Rule{src("00000000-0000-4000-8000-00000000b00a", "one"), src("00000000-0000-4000-8000-00000000b00b", "two")},
		Version:   "test",
		TaxonomyV: tax.Version,
	}
	p, err := Compile(rs)
	if err != nil {
		t.Fatal(err)
	}
	// Two logsource preds (channel, event_id), one shared Image pred, and
	// two distinct CommandLine preds.
	if len(p.Preds) != 5 {
		for _, pr := range p.Preds {
			t.Logf("pred %s", pr.Key)
		}
		t.Fatalf("got %d interned preds, want 5", len(p.Preds))
	}
	if p.Leaves() != 8 {
		t.Fatalf("got %d leaves, want 8", p.Leaves())
	}
	if got := p.ByField["Image"]; len(got) != 1 {
		t.Fatalf("ByField[Image] = %v, want one shared pred", got)
	}
	seen := map[string]bool{}
	for _, pr := range p.Preds {
		if seen[pr.Key] {
			t.Fatalf("pred %s interned twice", pr.Key)
		}
		seen[pr.Key] = true
	}
}

// Keys must separate everything the matcher depends on: the kind of a
// value, the modifier order, and keyword versus field.
func TestPredKeySeparatesWhatTheMatcherDependsOn(t *testing.T) {
	tax, err := sigma.LoadTaxonomy("../v1/testdata/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	y := `
title: t
id: 00000000-0000-4000-8000-00000000b00c
level: low
logsource: {product: windows, category: process_creation}
detection:
  a: {CommandLine|wide|base64: 'x'}
  b: {CommandLine|base64|wide: 'x'}
  c: {CommandLine: null}
  d: {CommandLine: 'null'}
  e: {CommandLine: ["a', 'b"]}
  f: {CommandLine: ['a', 'b']}
  g: ['CommandLine']
  condition: 1 of them
`
	r, lerr := sigma.LoadRuleBytes("k", []byte(y), tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	p, err := Compile(&sigma.RuleSet{Rules: []sigma.Rule{*r}, Version: "x", TaxonomyV: tax.Version})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Preds) != 2+7 {
		for _, pr := range p.Preds {
			t.Logf("pred %s", pr.Key)
		}
		t.Fatalf("got %d preds, want 9 distinct", len(p.Preds))
	}
}

func TestEquivalenceOnFixtures(t *testing.T) {
	for _, src := range fixtureSources(t) {
		t.Run(src.name, func(t *testing.T) {
			evs := genEvents(src.rs, 40, 1)
			res := compareEngines(t, src.rs, evs)
			if res.matched == 0 {
				t.Fatal("no verdict matched; the comparison proves nothing")
			}
			t.Logf("%d rules, %d events, %d verdicts, %d matched, digests %v",
				res.rules, res.events, res.verdicts, res.matched, res.digests)
		})
	}
}

// TestEquivalenceOnCorpus is the S-70 acceptance: over every accepted
// SigmaHQ rule, v2's digest equals v1's on every partition.
// SIGNALMAN_EQUIV_PER_RULE scales the stream for a longer run.
func TestEquivalenceOnCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus equivalence is not a short test")
	}
	rs := corpusSource(t)
	per := 1
	if s := os.Getenv("SIGNALMAN_EQUIV_PER_RULE"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		per = n
	}
	evs := genEvents(rs, per, 2)
	res := compareEngines(t, rs, evs)
	if res.matched == 0 {
		t.Fatal("no verdict matched; the comparison proves nothing")
	}
	t.Logf("corpus: %d rules, %d events, %d verdicts, %d matched, digests %v",
		res.rules, res.events, res.verdicts, res.matched, res.digests)
}

// TestRuleIndependence: a rule's verdict does not depend on which other
// rules share its interned predicates. Compiled alone and compiled with
// every other rule, each rule must give the same verdict on every event,
// and a shuffled rule set must give the same digest.
func TestRuleIndependence(t *testing.T) {
	for _, src := range fixtureSources(t) {
		t.Run(src.name, func(t *testing.T) {
			checkIndependence(t, src.rs, genEvents(src.rs, 20, 3), len(src.rs.Rules))
		})
	}
	t.Run("corpus", func(t *testing.T) {
		if testing.Short() {
			t.Skip("corpus is not a short test")
		}
		rs := corpusSource(t)
		// Every rule alone would be 1,236 compiles over the stream; a fixed
		// sample of rules keeps the run short and still crosses many shared
		// predicates.
		checkIndependence(t, rs, genEvents(rs, 1, 4)[:400], 60)
	})
}

func checkIndependence(t *testing.T, rs *sigma.RuleSet, evs []*event.Event, sample int) {
	t.Helper()
	full := New(rs)
	fullOut := make([][]event.Verdict, len(evs))
	for i, ev := range evs {
		fullOut[i] = full.Evaluate(ev)
	}

	rng := rand.New(rand.NewSource(5))
	idx := rng.Perm(len(rs.Rules))
	if sample < len(idx) {
		idx = idx[:sample]
	}
	for _, ri := range idx {
		alone := New(&sigma.RuleSet{Rules: rs.Rules[ri : ri+1], Version: rs.Version, TaxonomyV: rs.TaxonomyV})
		for i, ev := range evs {
			got := alone.Evaluate(ev)
			if len(got) != 1 || got[0].Matched != fullOut[i][ri].Matched {
				t.Fatalf("rule %s alone = %v, within the set = %v on event %v",
					rs.Rules[ri].ID, got, fullOut[i][ri], ev.Fields)
			}
		}
	}

	for k := 0; k < 3; k++ {
		shuffled := &sigma.RuleSet{Rules: append([]sigma.Rule(nil), rs.Rules...), Version: rs.Version, TaxonomyV: rs.TaxonomyV}
		rng.Shuffle(len(shuffled.Rules), func(a, b int) {
			shuffled.Rules[a], shuffled.Rules[b] = shuffled.Rules[b], shuffled.Rules[a]
		})
		// Same rules, different load order, different interned table:
		// the per-rule verdicts must not move.
		pos := map[string]int{}
		for i, r := range rs.Rules {
			pos[r.ID] = i
		}
		e := New(shuffled)
		for i, ev := range evs {
			for _, v := range e.Evaluate(ev) {
				if v.Matched != fullOut[i][pos[v.RuleID]].Matched {
					t.Fatalf("shuffle %d moved rule %s on event %v", k, v.RuleID, ev.Fields)
				}
			}
		}
	}
}

// Evaluation must not write to the evaluator: the shadow lane hands one
// event to both engines at once, and one evaluator serves many workers.
func TestEvaluateIsSafeConcurrently(t *testing.T) {
	rs := v1Fixtures(t)
	e := New(rs)
	evs := genEvents(rs, 20, 6)
	want := make([][]event.Verdict, len(evs))
	for i, ev := range evs {
		want[i] = e.Evaluate(ev)
	}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf []event.Verdict
			for i, ev := range evs {
				buf = e.EvaluateInto(buf[:0], ev)
				for j := range buf {
					if buf[j] != want[i][j] {
						t.Errorf("concurrent verdict differs: %+v vs %+v", buf[j], want[i][j])
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}
