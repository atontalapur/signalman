package v1

import (
	"sync"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

func load(t *testing.T) *sigma.RuleSet {
	t.Helper()
	tax, err := sigma.LoadTaxonomy("testdata/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	rs, errs, err := sigma.LoadRuleSet("testdata/rules", tax)
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 0 {
		t.Fatalf("fixtures must all load: %v", errs)
	}
	if len(rs.Rules) != 3 {
		t.Fatalf("expected 3 fixture rules, got %d", len(rs.Rules))
	}
	return rs
}

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

func TestEvaluateReturnsOneVerdictPerRule(t *testing.T) {
	rs := load(t)
	e := New(rs)
	vs := e.Evaluate(sysmonDump())
	if len(vs) != len(rs.Rules) {
		t.Fatalf("got %d verdicts for %d rules", len(vs), len(rs.Rules))
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if seen[v.RuleID] {
			t.Fatalf("rule %s got two verdicts", v.RuleID)
		}
		seen[v.RuleID] = true
	}
	for _, r := range rs.Rules {
		if !seen[r.ID] {
			t.Fatalf("rule %s got no verdict", r.ID)
		}
	}
}

func TestEvaluateVerdictsAreInRuleIDOrder(t *testing.T) {
	rs := load(t)
	vs := New(rs).Evaluate(sysmonDump())
	for i := 1; i < len(vs); i++ {
		if vs[i-1].RuleID >= vs[i].RuleID {
			t.Fatalf("verdict %d rule %s does not sort before %s",
				i, vs[i-1].RuleID, vs[i].RuleID)
		}
	}
}

func TestEvaluateCarriesEventAndVersionIdentity(t *testing.T) {
	rs := load(t)
	ev := sysmonDump()
	for _, v := range New(rs).Evaluate(ev) {
		if v.Seq != ev.Seq || v.Partition != ev.Partition {
			t.Fatalf("verdict does not carry the event identity: %+v", v)
		}
		if v.Engine != Name {
			t.Fatalf("engine = %q want %q", v.Engine, Name)
		}
		if v.RuleSetV != rs.Version || v.TaxonomyV != rs.TaxonomyV {
			t.Fatalf("verdict does not carry both versions: %+v", v)
		}
	}
}

func TestEvaluateMatchesTheRuleThatShould(t *testing.T) {
	rs := load(t)
	matched := map[string]bool{}
	for _, v := range New(rs).Evaluate(sysmonDump()) {
		matched[v.RuleID] = v.Matched
	}
	if !matched["1f1a1f1a-0001-4000-8000-000000000001"] {
		t.Fatal("the comsvcs minidump rule should match this event")
	}
	if matched["2f2a2f2a-0001-4000-8000-000000000001"] {
		t.Fatal("the network rule is on another logsource and must not match")
	}
}

func TestLogsourceMismatchIsAnExplicitFalseVerdict(t *testing.T) {
	// The invariant: every admitted event yields exactly one verdict per
	// enabled rule. A rule whose logsource does not cover the event emits
	// false, never an absent verdict, because "did not match" and "was
	// never evaluated" have to stay distinguishable.
	rs := load(t)
	ev := &event.Event{
		Seq: 1,
		Fields: map[string]event.Value{
			"channel":         event.String("Microsoft-Windows-Sysmon/Operational"),
			"event_id":        event.Int(3),
			"DestinationPort": event.Int(4444),
		},
	}
	vs := New(rs).Evaluate(ev)
	if len(vs) != len(rs.Rules) {
		t.Fatalf("got %d verdicts for %d rules", len(vs), len(rs.Rules))
	}
	byID := map[string]event.Verdict{}
	for _, v := range vs {
		byID[v.RuleID] = v
	}
	if !byID["2f2a2f2a-0001-4000-8000-000000000001"].Matched {
		t.Fatal("the network rule covers this event and should match it")
	}
	if byID["1f1a1f1a-0001-4000-8000-000000000001"].Matched {
		t.Fatal("a process_creation rule must not match a network event")
	}
}

func TestLogsourceMismatchDoesNotConsultTheCondition(t *testing.T) {
	// An event carrying fields a rule's condition would match, but on the
	// wrong logsource, must still come back false. Otherwise the taxonomy
	// is decoration.
	rs := load(t)
	ev := &event.Event{
		Seq: 2,
		Fields: map[string]event.Value{
			"channel":     event.String("Some-Other-Channel"),
			"event_id":    event.Int(99),
			"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
			"CommandLine": event.String(`rundll32.exe comsvcs.dll, MiniDump 624 C:\t.dmp full`),
		},
	}
	for _, v := range New(rs).Evaluate(ev) {
		if v.Matched {
			t.Fatalf("rule %s matched an event outside every mapped logsource", v.RuleID)
		}
	}
}

func TestEvaluateIsDeterministic(t *testing.T) {
	rs := load(t)
	e := New(rs)
	first := e.Evaluate(sysmonDump())
	for i := 0; i < 20; i++ {
		got := e.Evaluate(sysmonDump())
		if len(got) != len(first) {
			t.Fatalf("run %d returned %d verdicts, want %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("run %d verdict %d = %+v, want %+v", i, j, got[j], first[j])
			}
		}
	}
}

func TestEvaluateIsSafeForConcurrentUse(t *testing.T) {
	// The shadow lane in Plan G runs two engines over the same event at
	// once. Evaluation has to be read-only on both the rule set and the
	// event, which this test pins under -race.
	rs := load(t)
	e := New(rs)
	want := e.Evaluate(sysmonDump())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev := sysmonDump()
			for j := 0; j < 25; j++ {
				got := e.Evaluate(ev)
				for k := range got {
					if got[k] != want[k] {
						t.Errorf("concurrent verdict %d = %+v, want %+v", k, got[k], want[k])
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}

func TestEvaluateIntoReusesTheBuffer(t *testing.T) {
	// The pipeline evaluates millions of events; one allocation per event
	// per rule is not acceptable, so callers can pass a buffer back in.
	rs := load(t)
	e := New(rs)
	buf := make([]event.Verdict, 0, len(rs.Rules))
	first := e.EvaluateInto(buf, sysmonDump())
	second := e.EvaluateInto(first[:0], sysmonDump())
	if len(second) != len(rs.Rules) {
		t.Fatalf("got %d verdicts, want %d", len(second), len(rs.Rules))
	}
	if &first[0] != &second[0] {
		t.Fatal("EvaluateInto must write into the buffer it was given")
	}
}

func TestEvaluateEmptyRuleSetIsEmptyNotNil(t *testing.T) {
	e := New(&sigma.RuleSet{Version: "v", TaxonomyV: "t"})
	vs := e.Evaluate(sysmonDump())
	if len(vs) != 0 {
		t.Fatalf("no rules means no verdicts, got %d", len(vs))
	}
}

func TestRulesAreIndependent(t *testing.T) {
	// One rule's verdict must not depend on which other rules are loaded.
	// This is what makes a digest divergence attributable to a single rule.
	rs := load(t)
	full := map[string]bool{}
	for _, v := range New(rs).Evaluate(sysmonDump()) {
		full[v.RuleID] = v.Matched
	}
	for i := range rs.Rules {
		alone := &sigma.RuleSet{
			Rules:     []sigma.Rule{rs.Rules[i]},
			Version:   rs.Version,
			TaxonomyV: rs.TaxonomyV,
		}
		vs := New(alone).Evaluate(sysmonDump())
		if len(vs) != 1 {
			t.Fatalf("one rule must give one verdict, got %d", len(vs))
		}
		if vs[0].Matched != full[rs.Rules[i].ID] {
			t.Fatalf("rule %s matched %v alone but %v in the full set",
				rs.Rules[i].ID, vs[0].Matched, full[rs.Rules[i].ID])
		}
	}
}
