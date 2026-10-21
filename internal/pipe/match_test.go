package pipe

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// subset is a second rule set: the same rules minus the last, under a
// different version, so verdict records show which one evaluated them.
func subset(rs *sigma.RuleSet, version string) *sigma.RuleSet {
	cp := *rs
	cp.Rules = rs.Rules[:len(rs.Rules)-1]
	cp.Version = version
	return &cp
}

// heldEngine blocks its first evaluation until released, so a test can
// reload the slot while a batch is provably mid-evaluation.
type heldEngine struct {
	Engine
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func hold(e Engine) *heldEngine {
	return &heldEngine{Engine: e, started: make(chan struct{}), release: make(chan struct{})}
}

func (h *heldEngine) EvaluateInto(dst []event.Verdict, ev *event.Event) []event.Verdict {
	h.once.Do(func() { close(h.started); <-h.release })
	return h.Engine.EvaluateInto(dst, ev)
}

func verdictRecords(t *testing.T, b broker.Broker) []EventVerdicts {
	t.Helper()
	var out []EventVerdicts
	for _, r := range readAll(t, b, TopicVerdictsV1) {
		var ev EventVerdicts
		if err := json.Unmarshal(r.Value, &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

func TestReloadMidBatchTakesEffectAtTheNextBatch(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(1000))
	r := newRig(t, mem, mem)
	a := hold(V1(r.rs))
	slot := NewSlot(a, r.m)
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := map[string]bool{}
	for _, rec := range func() []broker.Record {
		var rs []broker.Record
		for i := 0; i < 60; i++ {
			if i%7 != 6 {
				rs = append(rs, genRaw(i))
			}
		}
		return rs
	}() {
		if err := mem.Produce(context.Background(), []broker.Record{rec}); err != nil {
			t.Fatal(err)
		}
	}
	end, _ := mem.EndOffsets(context.Background(), TopicEventsRaw)
	for part, n := range end {
		for s := int64(0); s < n; s++ {
			first[fmt.Sprint(part, "/", s)] = true
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- p.Run(ctx) }()

	<-a.started
	b := subset(r.rs, "reloaded")
	slot.Store(V1(b))
	close(a.release)

	// Wait for the first batch to commit, then feed a second one.
	for {
		if done, _ := committedAll(mem); done {
			break
		}
		time.Sleep(time.Millisecond)
	}
	produceRaw(t, mem, 0, 30)
	for {
		if done, _ := committedAll(mem); done {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-errc

	for _, ev := range verdictRecords(t, mem) {
		key := fmt.Sprint(ev.Partition, "/", ev.Seq)
		if first[key] {
			if ev.RuleSetV != r.rs.Version || len(ev.Verdicts) != len(r.rs.Rules) {
				t.Fatalf("%s was in flight when the reload landed, yet ran under %s with %d verdicts", key, ev.RuleSetV, len(ev.Verdicts))
			}
		} else if ev.RuleSetV != "reloaded" || len(ev.Verdicts) != len(b.Rules) {
			t.Fatalf("%s was polled after the reload, yet ran under %s with %d verdicts", key, ev.RuleSetV, len(ev.Verdicts))
		}
	}
}

func TestNoBatchStraddlesTwoRuleSetsUnderConstantReload(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(9))
	g := &gated{Broker: mem}
	r := newRig(t, g, mem)
	versions := []*sigma.RuleSet{r.rs, subset(r.rs, "alt-1"), subset(r.rs, "alt-2")}
	slot := NewSlot(V1(versions[0]), r.m)
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Each commit closes one batch. Record the seqs every commit covered.
	type span struct{ from, to map[int32]int64 }
	var spans []span
	prev := map[int32]int64{}
	g.onCommit = func(next map[broker.TopicPartition]int64) {
		s := span{from: map[int32]int64{}, to: map[int32]int64{}}
		for tp, off := range next {
			s.from[tp.Partition], s.to[tp.Partition] = prev[tp.Partition], off
			prev[tp.Partition] = off
		}
		spans = append(spans, s)
	}

	stop := make(chan struct{})
	reloads := make(chan int, 1)
	go func() {
		n := 0
		for {
			select {
			case <-stop:
				reloads <- n
				return
			default:
			}
			n++
			slot.Store(V1(versions[n%len(versions)]))
			time.Sleep(50 * time.Microsecond)
		}
	}()
	produceRaw(t, mem, 0, 600)
	runUntilCommitted(t, p, mem)
	close(stop)
	if n := <-reloads; n < 10 {
		t.Fatalf("only %d reloads happened; the test proves nothing", n)
	}

	version := map[string]string{}
	for _, ev := range verdictRecords(t, mem) {
		version[fmt.Sprint(ev.Partition, "/", ev.Seq)] = ev.RuleSetV
	}
	seen := map[string]bool{}
	for i, s := range spans {
		got := map[string]bool{}
		for part, to := range s.to {
			for seq := s.from[part]; seq < to; seq++ {
				if v, ok := version[fmt.Sprint(part, "/", seq)]; ok {
					got[v] = true
				}
			}
		}
		if len(got) > 1 {
			t.Fatalf("batch %d was evaluated under %d rule sets: %v", i, len(got), got)
		}
		for v := range got {
			seen[v] = true
		}
	}
	if len(seen) < 2 {
		t.Fatalf("every batch ran under one version (%v); the reloads never landed", seen)
	}
}

func TestRuleSetVersionInfoTracksTheActiveVersion(t *testing.T) {
	mem := newMemory()
	r := newRig(t, mem, mem)
	slot := NewSlot(V1(r.rs), r.m)
	if got := testutil.ToFloat64(r.m.RuleSetVersion.WithLabelValues(r.rs.Version, r.rs.TaxonomyV)); got != 1 {
		t.Fatalf("initial version info = %v", got)
	}
	b := subset(r.rs, "next")
	slot.Store(V1(b))
	if n := testutil.CollectAndCount(r.m.RuleSetVersion); n != 1 {
		t.Fatalf("%d version series after a reload; only the active one is exported", n)
	}
	if got := testutil.ToFloat64(r.m.RuleSetVersion.WithLabelValues("next", b.TaxonomyV)); got != 1 {
		t.Fatalf("reloaded version info = %v", got)
	}
	if n, ok := slot.RuleCount(r.rs.Version); !ok || n != len(r.rs.Rules) {
		t.Fatal("a version that was ever active stays known, so its verdicts can be audited")
	}
	if n, ok := slot.RuleCount("next"); !ok || n != len(b.Rules) {
		t.Fatal("the active version is known")
	}
	if _, ok := slot.RuleCount("never"); ok {
		t.Fatal("an unknown version is unknown")
	}
}

func TestMatchesGoToAlertsKeyedByRuleID(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	const n = 90
	produceRaw(t, mem, 0, n)
	p, err := New(testConfig(), r.b, r.norm, NewSlot(V1(r.rs), r.m), r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	runUntilCommitted(t, p, mem)

	matched := 0
	for _, ev := range verdictRecords(t, mem) {
		for _, v := range ev.Verdicts {
			if v.Matched {
				matched++
			}
		}
	}
	alerts := readAll(t, mem, TopicAlerts)
	if matched == 0 || len(alerts) != matched {
		t.Fatalf("%d alerts for %d matched verdicts", len(alerts), matched)
	}
	for _, rec := range alerts {
		var a Alert
		if err := json.Unmarshal(rec.Value, &a); err != nil {
			t.Fatal(err)
		}
		if string(rec.Key) != a.RuleID || a.RuleID != dumpRuleID {
			t.Fatalf("alert keyed %q for rule %q", rec.Key, a.RuleID)
		}
		if a.RuleTitle != "LSASS Memory Dump via comsvcs" || a.Severity != "high" || a.Source != "sysmon" || a.HostID == "" {
			t.Fatalf("alert %+v", a)
		}
		if a.Fields["Image"] != `C:\Windows\System32\rundll32.exe` || a.Fields["event_id"] != "1" {
			t.Fatalf("alert fields %v", a.Fields)
		}
		if a.EventTime.IsZero() || a.Raw == "" {
			t.Fatalf("alert carries event time and raw: %+v", a)
		}
	}
	if got := testutil.ToFloat64(r.m.RuleMatches.WithLabelValues(dumpRuleID)); got != float64(matched) {
		t.Fatalf("rule matches counter = %v, want %d", got, matched)
	}
	if got := testutil.ToFloat64(r.m.Verdicts.WithLabelValues("v1", "true")); got != float64(matched) {
		t.Fatalf("matched verdicts counter = %v, want %d", got, matched)
	}
	evaluated := n - n/7
	if got := total(r.m.Verdicts); got != float64(evaluated*len(r.rs.Rules)) {
		t.Fatalf("verdicts counter = %v, want %d", got, evaluated*len(r.rs.Rules))
	}
}
