package pipe

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func shadowRecords(t *testing.T, b broker.Broker) []EventVerdicts {
	t.Helper()
	var out []EventVerdicts
	for _, r := range readAll(t, b, TopicVerdictsV2) {
		var ev EventVerdicts
		if err := json.Unmarshal(r.Value, &ev); err != nil {
			t.Fatal(err)
		}
		if r.Partition != ev.Partition {
			t.Fatalf("verdicts.v2 record for partition %d written to partition %d", ev.Partition, r.Partition)
		}
		out = append(out, ev)
	}
	return out
}

// failingEngine panics on every seq fail selects, standing in for a v2 bug
// that the shadow lane must survive and the differ must see.
type failingEngine struct {
	Engine
	fail func(seq uint64) bool
}

func (f failingEngine) EvaluateInto(dst []event.Verdict, ev *event.Event) []event.Verdict {
	if f.fail(ev.Seq) {
		panic(fmt.Sprintf("injected shadow failure at seq %d", ev.Seq))
	}
	return f.Engine.EvaluateInto(dst, ev)
}

// shortEngine drops the last verdict on selected seqs.
type shortEngine struct {
	Engine
	short func(seq uint64) bool
}

func (s shortEngine) EvaluateInto(dst []event.Verdict, ev *event.Event) []event.Verdict {
	out := s.Engine.EvaluateInto(dst, ev)
	if s.short(ev.Seq) {
		return out[:len(out)-1]
	}
	return out
}

func TestShadowLaneWritesVerdictsV2AndNoAlerts(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	const n = 140
	produceRaw(t, mem, 0, n)
	slot := NewSlot(V1(r.rs), r.m)
	if err := slot.StoreWithShadow(V1(r.rs), V2(r.rs)); err != nil {
		t.Fatal(err)
	}
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	runUntilCommitted(t, p, mem)

	primary := map[string]EventVerdicts{}
	matched := 0
	for _, ev := range verdictRecords(t, mem) {
		if ev.Shadow != "v2" {
			t.Fatalf("seq %d: a shadowed v1 record names its shadow, got %q", ev.Seq, ev.Shadow)
		}
		primary[fmt.Sprint(ev.Partition, "/", ev.Seq)] = ev
		for _, v := range ev.Verdicts {
			if v.Matched {
				matched++
			}
		}
	}
	shadow := shadowRecords(t, mem)
	if len(shadow) != len(primary) || len(shadow) != n-n/7 {
		t.Fatalf("%d verdicts.v2 records, %d verdicts.v1 records, %d evaluated events", len(shadow), len(primary), n-n/7)
	}
	for _, ev := range shadow {
		key := fmt.Sprint(ev.Partition, "/", ev.Seq)
		want, ok := primary[key]
		if !ok {
			t.Fatalf("%s has a v2 record and no v1 record", key)
		}
		if ev.Engine != "v2" || ev.RuleSetV != want.RuleSetV || ev.TaxonomyV != want.TaxonomyV || ev.Shadow != "" {
			t.Fatalf("%s: v2 record identity %+v", key, ev)
		}
		if len(ev.Verdicts) != len(r.rs.Rules) {
			t.Fatalf("%s: %d v2 verdicts for %d rules", key, len(ev.Verdicts), len(r.rs.Rules))
		}
		for i, v := range ev.Verdicts {
			if v != want.Verdicts[i] {
				t.Fatalf("%s: v2 %+v, v1 %+v", key, v, want.Verdicts[i])
			}
		}
	}
	// The shadow emits no alerts: one alert per v1 match and no more.
	if got := len(readAll(t, mem, TopicAlerts)); matched == 0 || got != matched {
		t.Fatalf("%d alerts for %d v1 matches", got, matched)
	}
	if got := testutil.ToFloat64(r.m.Verdicts.WithLabelValues("v2", "true")); got != float64(matched) {
		t.Fatalf("v2 matched verdicts counter = %v, want %d", got, matched)
	}
}

func TestUnshadowedRecordsDoNotNameAShadow(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	produceRaw(t, mem, 0, 20)
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)
	for _, ev := range verdictRecords(t, mem) {
		if ev.Shadow != "" {
			t.Fatalf("seq %d names shadow %q with no shadow lane", ev.Seq, ev.Shadow)
		}
	}
	if got := len(readAll(t, mem, TopicVerdictsV2)); got != 0 {
		t.Fatalf("%d verdicts.v2 records with no shadow lane", got)
	}
}

func TestShadowFailureIsRecordedAndDoesNotStopThePipeline(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	const n = 140
	produceRaw(t, mem, 0, n)
	slot := NewSlot(V1(r.rs), r.m)
	panics := func(seq uint64) bool { return seq%5 == 0 }
	shorts := func(seq uint64) bool { return seq%5 == 1 }
	shadow := shortEngine{Engine: failingEngine{Engine: V2(r.rs), fail: panics}, short: shorts}
	if err := slot.StoreWithShadow(V1(r.rs), shadow); err != nil {
		t.Fatal(err)
	}
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	runUntilCommitted(t, p, mem)

	failed := 0
	for _, ev := range verdictRecords(t, mem) {
		if len(ev.Verdicts) != len(r.rs.Rules) {
			t.Fatalf("v1 is untouched by a shadow failure: seq %d has %d verdicts", ev.Seq, len(ev.Verdicts))
		}
		if panics(ev.Seq) || shorts(ev.Seq) {
			failed++
		}
	}
	for _, ev := range shadowRecords(t, mem) {
		if panics(ev.Seq) || shorts(ev.Seq) {
			t.Fatalf("seq %d: a failed shadow evaluation must leave no v2 record, not a partial one", ev.Seq)
		}
		if len(ev.Verdicts) != len(r.rs.Rules) {
			t.Fatalf("seq %d: %d v2 verdicts", ev.Seq, len(ev.Verdicts))
		}
	}
	if failed == 0 {
		t.Fatal("no shadow failures were injected; the test proves nothing")
	}
	if got := testutil.ToFloat64(r.m.ShadowFailures.WithLabelValues("v2")); got != float64(failed) {
		t.Fatalf("shadow failures counter = %v, want %d", got, failed)
	}
}

func TestStoreWithShadowRefusesMismatchedRuleSets(t *testing.T) {
	mem := newMemory()
	r := newRig(t, mem, mem)
	slot := NewSlot(V1(r.rs), r.m)
	other := subset(r.rs, "other")
	if err := slot.StoreWithShadow(V1(r.rs), V2(other)); err == nil {
		t.Fatal("a shadow under a different RuleSetV makes every verdict version skew")
	}
	if err := slot.StoreWithShadow(V1(r.rs), V1(r.rs)); err == nil {
		t.Fatal("a shadow with the primary's name would write to the primary's topic")
	}
	if slot.load().shadow != nil {
		t.Fatal("a refused store changed the slot")
	}
}

func TestReloadSwapsPrimaryAndShadowTogether(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(7))
	r := newRig(t, mem, mem)
	versions := []*sigma.RuleSet{r.rs, subset(r.rs, "alt-1"), subset(r.rs, "alt-2")}
	slot := NewSlot(V1(r.rs), r.m)
	if err := slot.StoreWithShadow(V1(r.rs), V2(r.rs)); err != nil {
		t.Fatal(err)
	}
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan int)
	go func() {
		n := 0
		for {
			select {
			case <-stop:
				done <- n
				return
			default:
			}
			n++
			rs := versions[n%len(versions)]
			if err := slot.StoreWithShadow(V1(rs), V2(rs)); err != nil {
				panic(err)
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()
	produceRaw(t, mem, 0, 400)
	runUntilCommitted(t, p, mem)
	close(stop)
	if n := <-done; n < 10 {
		t.Fatalf("only %d reloads happened; the test proves nothing", n)
	}
	v1 := map[string]string{}
	for _, ev := range verdictRecords(t, mem) {
		v1[fmt.Sprint(ev.Partition, "/", ev.Seq)] = ev.RuleSetV
	}
	versionsSeen := map[string]bool{}
	for _, ev := range shadowRecords(t, mem) {
		key := fmt.Sprint(ev.Partition, "/", ev.Seq)
		if v1[key] != ev.RuleSetV {
			t.Fatalf("%s: v1 ran under %s and v2 under %s; the pair was not swapped atomically", key, v1[key], ev.RuleSetV)
		}
		versionsSeen[ev.RuleSetV] = true
	}
	if len(versionsSeen) < 2 {
		t.Fatalf("every event ran under one version (%v); the reloads never landed", versionsSeen)
	}
}
