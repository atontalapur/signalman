package pipe

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	listRuleID    = "1f1a1f1a-0004-4000-8000-000000000004"
	networkRuleID = "2f2a2f2a-0001-4000-8000-000000000001"
)

func TestRolloutBucketIsPinned(t *testing.T) {
	// FNV-1a 32 of the rule id, mod 100. These values are the routing:
	// if they change, a restart moves rules between engines.
	for id, want := range map[string]int{
		dumpRuleID:    95,
		listRuleID:    33,
		networkRuleID: 67,
		"a":           20,
		"b":           77,
	} {
		if got := RolloutBucket(id); got != want {
			t.Fatalf("bucket(%q) = %d, want %d", id, got, want)
		}
	}
}

func TestAdvancingTheRolloutNeverMovesARuleBack(t *testing.T) {
	ids := make([]string, 2000)
	for i := range ids {
		ids[i] = fmt.Sprintf("%08x-rule-%d", i*2654435761, i)
	}
	for _, id := range ids {
		if ServedByShadow(id, 0) {
			t.Fatalf("%s served by the shadow at 0%%", id)
		}
		if !ServedByShadow(id, 100) {
			t.Fatalf("%s not served by the shadow at 100%%", id)
		}
		for p := 0; p < 100; p++ {
			if ServedByShadow(id, p) && !ServedByShadow(id, p+1) {
				t.Fatalf("%s moved back to the primary going from %d%% to %d%%", id, p, p+1)
			}
		}
	}
	// The split is close to the percentage, so 1% means about 1%.
	served := 0
	for _, id := range ids {
		if ServedByShadow(id, 10) {
			served++
		}
	}
	if served < 150 || served > 250 {
		t.Fatalf("10%% serves %d of %d rules", served, len(ids))
	}
}

func TestSetRolloutValidates(t *testing.T) {
	mem := newMemory()
	r := newRig(t, mem, mem)
	slot := NewSlot(V1(r.rs), r.m)
	if err := slot.SetRollout(10); err == nil {
		t.Fatal("no rule can be served by a shadow that is not there")
	}
	if err := slot.SetRollout(0); err != nil {
		t.Fatalf("0%% needs no shadow: %v", err)
	}
	if err := slot.StoreWithShadow(V1(r.rs), V2(r.rs)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []int{-1, 101} {
		if err := slot.SetRollout(bad); err == nil {
			t.Fatalf("%d%% accepted", bad)
		}
	}
	if err := slot.SetRollout(40); err != nil {
		t.Fatal(err)
	}
	if got := slot.Rollout(); got != 40 {
		t.Fatalf("rollout = %d", got)
	}
	if got := testutil.ToFloat64(r.m.RolloutPercent); got != 40 {
		t.Fatalf("rollout gauge = %v", got)
	}
	// A reload keeps the rollout: changing rules is not changing routing.
	if err := slot.StoreWithShadow(V1(r.rs), V2(r.rs)); err != nil {
		t.Fatal(err)
	}
	if got := slot.Rollout(); got != 40 {
		t.Fatalf("rollout after reload = %d", got)
	}
}

type alertKey struct {
	part int32
	seq  uint64
	rule string
}

func alertsByKey(t *testing.T, b broker.Broker) map[alertKey][]Alert {
	t.Helper()
	out := map[alertKey][]Alert{}
	for _, rec := range readAll(t, b, TopicAlerts) {
		var a Alert
		if err := json.Unmarshal(rec.Value, &a); err != nil {
			t.Fatal(err)
		}
		k := alertKey{a.Partition, a.Seq, a.RuleID}
		out[k] = append(out[k], a)
	}
	return out
}

func matchedKeys(t *testing.T, b broker.Broker) map[alertKey]bool {
	t.Helper()
	out := map[alertKey]bool{}
	for _, ev := range verdictRecords(t, b) {
		for _, v := range ev.Verdicts {
			if v.Matched {
				out[alertKey{ev.Partition, ev.Seq, v.RuleID}] = true
			}
		}
	}
	return out
}

func runServing(t *testing.T, percent int, shadow func(*rig) Engine) (*rig, *broker.Memory) {
	t.Helper()
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	produceRaw(t, mem, 0, 140)
	slot := NewSlot(V1(r.rs), r.m)
	if err := slot.StoreWithShadow(V1(r.rs), shadow(r)); err != nil {
		t.Fatal(err)
	}
	if err := slot.SetRollout(percent); err != nil {
		t.Fatal(err)
	}
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	runUntilCommitted(t, p, mem)
	return r, mem
}

func TestTheServingEngineEmitsTheAlerts(t *testing.T) {
	v2 := func(r *rig) Engine { return V2(r.rs) }
	for _, c := range []struct {
		percent int
		engine  string
	}{{0, "v1"}, {95, "v1"}, {96, "v2"}, {100, "v2"}} {
		t.Run(fmt.Sprint(c.percent), func(t *testing.T) {
			r, mem := runServing(t, c.percent, v2)
			want := matchedKeys(t, mem)
			got := alertsByKey(t, mem)
			if len(want) == 0 || len(got) != len(want) {
				t.Fatalf("%d alert keys for %d matches", len(got), len(want))
			}
			for k := range want {
				if len(got[k]) != 1 || got[k][0].Engine != c.engine {
					t.Fatalf("%v at %d%%: alerts %+v, want one from %s", k, c.percent, got[k], c.engine)
				}
			}
			// Both engines' verdicts are recorded whichever one serves.
			if n, m := len(verdictRecords(t, mem)), len(shadowRecords(t, mem)); n == 0 || n != m {
				t.Fatalf("%d v1 and %d v2 verdict records", n, m)
			}
			if got := testutil.ToFloat64(r.m.Alerts.WithLabelValues(c.engine, dumpRuleID)); got != float64(len(want)) {
				t.Fatalf("alerts counter for %s = %v, want %d", c.engine, got, len(want))
			}
		})
	}
}

func TestShadowFailureFallsBackToThePrimaryForServedRules(t *testing.T) {
	panics := func(seq uint64) bool { return seq%4 == 0 }
	_, mem := runServing(t, 100, func(r *rig) Engine { return failingEngine{Engine: V2(r.rs), fail: panics} })
	want := matchedKeys(t, mem)
	got := alertsByKey(t, mem)
	fellBack := 0
	for k := range want {
		if len(got[k]) != 1 {
			t.Fatalf("%v: %d alerts; a failed shadow must not cost or double an alert", k, len(got[k]))
		}
		engine := "v2"
		if panics(k.seq) {
			engine = "v1"
			fellBack++
		}
		if got[k][0].Engine != engine {
			t.Fatalf("%v: alert from %s, want %s", k, got[k][0].Engine, engine)
		}
	}
	if fellBack == 0 || len(got) != len(want) {
		t.Fatalf("%d fallbacks, %d alert keys for %d matches", fellBack, len(got), len(want))
	}
}

func TestExactlyOneAlertPerKeyWhileTheRolloutMoves(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(9))
	g := &gated{Broker: mem}
	r := newRig(t, g, mem)
	slot := NewSlot(V1(r.rs), r.m)
	if err := slot.StoreWithShadow(V1(r.rs), V2(r.rs)); err != nil {
		t.Fatal(err)
	}
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
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
	done := make(chan int)
	go func() {
		steps := []int{0, 34, 96, 100, 50, 0}
		n := 0
		for {
			select {
			case <-stop:
				done <- n
				return
			default:
			}
			n++
			if err := slot.SetRollout(steps[n%len(steps)]); err != nil {
				panic(err)
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()
	produceRaw(t, mem, 0, 600)
	runUntilCommitted(t, p, mem)
	close(stop)
	if n := <-done; n < 10 {
		t.Fatalf("only %d rollout changes happened; the test proves nothing", n)
	}

	want := matchedKeys(t, mem)
	got := alertsByKey(t, mem)
	engines := map[string]bool{}
	for k := range want {
		if len(got[k]) != 1 {
			t.Fatalf("%v: %d alerts", k, len(got[k]))
		}
		engines[got[k][0].Engine] = true
	}
	if len(got) != len(want) {
		t.Fatalf("%d alert keys for %d matches: an alert with no match", len(got), len(want))
	}
	if !engines["v1"] || !engines["v2"] {
		t.Fatalf("alerts only from %v; the rollout changes never landed", engines)
	}
	// A batch reads the rollout once, so within a batch one engine serves
	// the dump rule.
	for i, s := range spans {
		seen := map[string]bool{}
		for k, as := range got {
			if k.rule == dumpRuleID && int64(k.seq) >= s.from[k.part] && int64(k.seq) < s.to[k.part] {
				if _, ok := s.to[k.part]; ok {
					seen[as[0].Engine] = true
				}
			}
		}
		if len(seen) > 1 {
			t.Fatalf("batch %d served the dump rule from %v", i, seen)
		}
	}
}

func TestRolloutChangeTakesEffectAtTheNextBatch(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(1000))
	r := newRig(t, mem, mem)
	a := hold(V1(r.rs))
	slot := NewSlot(V1(r.rs), r.m)
	if err := slot.StoreWithShadow(a, V2(r.rs)); err != nil {
		t.Fatal(err)
	}
	if err := slot.SetRollout(100); err != nil {
		t.Fatal(err)
	}
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	produceRaw(t, mem, 0, 60)
	end, _ := mem.EndOffsets(context.Background(), TopicEventsRaw)
	first := map[alertKey]bool{}
	for part, n := range end {
		for s := int64(0); s < n; s++ {
			first[alertKey{part, uint64(s), dumpRuleID}] = true
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- p.Run(ctx) }()
	<-a.started
	// Roll back while the first batch is mid-evaluation.
	if err := slot.SetRollout(0); err != nil {
		t.Fatal(err)
	}
	close(a.release)
	waitCommitted := func() {
		for {
			if done, _ := committedAll(mem); done {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitCommitted()
	produceRaw(t, mem, 60, 60)
	waitCommitted()
	cancel()
	<-errc

	before, after := 0, 0
	for k, as := range alertsByKey(t, mem) {
		if len(as) != 1 {
			t.Fatalf("%v: %d alerts", k, len(as))
		}
		if first[k] {
			before++
			if as[0].Engine != "v2" {
				t.Fatalf("%v was in flight at the rollback, yet was served by %s", k, as[0].Engine)
			}
		} else {
			after++
			if as[0].Engine != "v1" {
				t.Fatalf("%v was polled after the rollback, yet was served by %s", k, as[0].Engine)
			}
		}
	}
	if before == 0 || after == 0 {
		t.Fatalf("%d alerts before and %d after the rollback", before, after)
	}
}

// blindEngine is a well-formed engine that never matches the canary rule.
type blindEngine struct{ Engine }

func (b blindEngine) EvaluateInto(dst []event.Verdict, ev *event.Event) []event.Verdict {
	out := b.Engine.EvaluateInto(dst, ev)
	for i := range out {
		if out[i].RuleID == CanaryRuleID {
			out[i].Matched = false
		}
	}
	return out
}

// The canary age is reset by the canary alert, from whichever engine
// serves the rule, so it pages on the alerts the SOC actually gets. A v2
// that wrongly says false for the canary while it serves the rule writes no
// canary alert, and the age keeps climbing.
func TestCanaryAgeAndRuleMatchesFollowTheServedAlert(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1790000000, 0)}
	mem := newMemory()
	r := newRigClock(t, mem, mem, clk.Now)
	r.rs = loadShippedRules(t)
	slot := NewSlot(V1(r.rs), r.m)
	if err := slot.StoreWithShadow(V1(r.rs), blindEngine{V2(r.rs)}); err != nil {
		t.Fatal(err)
	}
	if err := slot.SetRollout(100); err != nil {
		t.Fatal(err)
	}
	if err := NewCanary(mem, r.m, clk.Now, nil).Inject(context.Background()); err != nil {
		t.Fatal(err)
	}
	clk.Add(60 * time.Second)
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	runUntilCommitted(t, p, mem)
	clk.Add(5 * time.Second)
	if n := len(alertsByKey(t, mem)); n != 0 {
		t.Fatalf("%d alerts; v2 serves the canary rule and never matches it", n)
	}
	for part := int32(0); part < testPartitions; part++ {
		if a, ok := r.m.CanaryAge.Age(part); !ok || a != 65*time.Second {
			t.Fatalf("partition %d canary age %v (tracked %v), want 65s: no canary alert was served", part, a, ok)
		}
	}
	if got := testutil.ToFloat64(r.m.RuleMatches.WithLabelValues(CanaryRuleID)); got != 0 {
		t.Fatalf("rule_matches_total for the canary = %v; it counts served alerts, and none was", got)
	}
}

// A rollout that hands the canary rule to v2, or a v2 failure on the
// canary event, still resets the canary: the served alert comes from v2,
// or from v1 when v2 failed on the event.
func TestCanaryResetsWhicheverEngineServesIt(t *testing.T) {
	for name, shadow := range map[string]func(*rig) Engine{
		"v2 serves": func(r *rig) Engine { return V2(r.rs) },
		"v2 panics": func(r *rig) Engine { return failingEngine{Engine: V2(r.rs), fail: func(uint64) bool { return true }} },
	} {
		t.Run(name, func(t *testing.T) {
			clk := &fakeClock{t: time.Unix(1790000000, 0)}
			mem := newMemory()
			r := newRigClock(t, mem, mem, clk.Now)
			r.rs = loadShippedRules(t)
			slot := NewSlot(V1(r.rs), r.m)
			if err := slot.StoreWithShadow(V1(r.rs), shadow(r)); err != nil {
				t.Fatal(err)
			}
			if err := slot.SetRollout(100); err != nil {
				t.Fatal(err)
			}
			if err := NewCanary(mem, r.m, clk.Now, nil).Inject(context.Background()); err != nil {
				t.Fatal(err)
			}
			clk.Add(60 * time.Second)
			p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
			if err != nil {
				t.Fatal(err)
			}
			runUntilCommitted(t, p, mem)
			clk.Add(5 * time.Second)
			for part := int32(0); part < testPartitions; part++ {
				if a, ok := r.m.CanaryAge.Age(part); !ok || a != 5*time.Second {
					t.Fatalf("partition %d canary age %v (tracked %v), want 5s: the canary alert did not reset it", part, a, ok)
				}
			}
			want := "v2"
			if name == "v2 panics" {
				want = "v1"
			}
			n := 0
			for k, as := range alertsByKey(t, mem) {
				if k.rule != CanaryRuleID || len(as) != 1 || as[0].Engine != want {
					t.Fatalf("%v: alerts %+v, want one canary alert from %s", k, as, want)
				}
				n++
			}
			if n != testPartitions {
				t.Fatalf("%d canary alerts for %d partitions", n, testPartitions)
			}
		})
	}
}
