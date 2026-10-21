package pipe

import (
	"encoding/json"
	"testing"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// topicVerdicts reads every EventVerdicts record on topic.
func topicVerdicts(t *testing.T, b broker.Broker, topic string) []EventVerdicts {
	t.Helper()
	var out []EventVerdicts
	for _, r := range readAll(t, b, topic) {
		var ev EventVerdicts
		if err := json.Unmarshal(r.Value, &ev); err != nil {
			t.Fatal(err)
		}
		if r.Partition != ev.Partition {
			t.Fatalf("%s record for partition %d written to partition %d", topic, ev.Partition, r.Partition)
		}
		out = append(out, ev)
	}
	return out
}

// runV2Primary runs n events with v2 serving and, if oracle is not nil, v1
// beside it as the shadow.
func runV2Primary(t *testing.T, n int, oracle func(*rig) Engine) (*rig, *broker.Memory, *Slot) {
	t.Helper()
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	produceRaw(t, mem, 0, n)
	slot := NewSlot(V2(r.rs), r.m)
	if oracle != nil {
		if err := slot.StoreWithShadow(V2(r.rs), oracle(r)); err != nil {
			t.Fatal(err)
		}
	}
	p, err := New(testConfig(), r.b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	runUntilCommitted(t, p, mem)
	return r, mem, slot
}

// v2Keys is the matched (partition, seq, rule) keys in verdicts.v2.
func v2Keys(t *testing.T, b broker.Broker) map[alertKey]bool {
	t.Helper()
	out := map[alertKey]bool{}
	for _, ev := range topicVerdicts(t, b, TopicVerdictsV2) {
		for _, v := range ev.Verdicts {
			if v.Matched {
				out[alertKey{ev.Partition, ev.Seq, v.RuleID}] = true
			}
		}
	}
	return out
}

// checkV2Serves holds the invariants with v2 primary: every admitted event
// has exactly one verdicts.v2 record or one drop, each record has one
// verdict per rule, and there is exactly one alert per matched key, served
// by v2.
func checkV2Serves(t *testing.T, r *rig, mem *broker.Memory, n int) {
	t.Helper()
	primary := topicVerdicts(t, mem, TopicVerdictsV2)
	drops := readAll(t, mem, TopicDrops)
	if len(primary)+len(drops) != n || len(primary) != n-n/7 {
		t.Fatalf("%d verdicts.v2 records and %d drops for %d admitted events", len(primary), len(drops), n)
	}
	seen := map[alertKey]bool{}
	for _, ev := range primary {
		k := alertKey{ev.Partition, ev.Seq, ""}
		if seen[k] {
			t.Fatalf("two verdict records for %v", k)
		}
		seen[k] = true
		if ev.Engine != "v2" || len(ev.Verdicts) != len(r.rs.Rules) {
			t.Fatalf("seq %d: engine %s with %d verdicts for %d rules", ev.Seq, ev.Engine, len(ev.Verdicts), len(r.rs.Rules))
		}
	}
	want := v2Keys(t, mem)
	got := alertsByKey(t, mem)
	if len(want) == 0 || len(got) != len(want) {
		t.Fatalf("%d alert keys for %d v2 matches", len(got), len(want))
	}
	for k := range want {
		if len(got[k]) != 1 || got[k][0].Engine != "v2" {
			t.Fatalf("%v: alerts %+v, want exactly one from v2", k, got[k])
		}
	}
	var served [2]float64
	for i, eng := range []string{"v1", "v2"} {
		for _, rule := range r.rs.Rules {
			served[i] += testutil.ToFloat64(r.m.Alerts.WithLabelValues(eng, rule.ID))
		}
	}
	if served[0] != 0 || served[1] != float64(len(want)) {
		t.Fatalf("alerts counter: v1 %v, v2 %v, want 0 and %d", served[0], served[1], len(want))
	}
}

func TestV2PrimaryServesEveryAlertAndV1OnlyShadows(t *testing.T) {
	const n = 140
	r, mem, _ := runV2Primary(t, n, func(r *rig) Engine { return V1(r.rs) })
	checkV2Serves(t, r, mem, n)

	// v1 still evaluates every event for the differ, and the primary's
	// records say a v1 record is owed.
	primary := topicVerdicts(t, mem, TopicVerdictsV2)
	oracle := topicVerdicts(t, mem, TopicVerdictsV1)
	if len(oracle) != len(primary) {
		t.Fatalf("%d verdicts.v1 records for %d verdicts.v2 records", len(oracle), len(primary))
	}
	for _, ev := range primary {
		if ev.Shadow != "v1" {
			t.Fatalf("seq %d: primary record names shadow %q, want v1", ev.Seq, ev.Shadow)
		}
	}
	for i, ev := range oracle {
		if ev.Engine != "v1" || ev.Shadow != "" || ev.Seq != primary[i].Seq || len(ev.Verdicts) != len(r.rs.Rules) {
			t.Fatalf("verdicts.v1 record %d: %+v", i, ev)
		}
		for j, v := range ev.Verdicts {
			if v != primary[i].Verdicts[j] {
				t.Fatalf("seq %d rule %s: v1 %v, v2 %v", ev.Seq, v.RuleID, v.Matched, primary[i].Verdicts[j].Matched)
			}
		}
	}
	if got := testutil.ToFloat64(r.m.RolloutPercent); got != 100 {
		t.Fatalf("signalman_rollout_percent %v with v2 serving every rule, want 100", got)
	}
}

func TestV2PrimaryWithoutTheOracle(t *testing.T) {
	const n = 70
	r, mem, _ := runV2Primary(t, n, nil)
	checkV2Serves(t, r, mem, n)
	if recs := readAll(t, mem, TopicVerdictsV1); len(recs) != 0 {
		t.Fatalf("%d verdicts.v1 records with v1 out of the pipeline", len(recs))
	}
	for _, ev := range topicVerdicts(t, mem, TopicVerdictsV2) {
		if ev.Shadow != "" {
			t.Fatalf("seq %d names shadow %q with no shadow", ev.Seq, ev.Shadow)
		}
	}
}

// A failing v1 oracle costs a v1 record, which the differ reports as
// missing, and never an alert: v1 is not in the serving path.
func TestAFailingOracleCostsNoAlert(t *testing.T) {
	const n = 140
	fails := func(seq uint64) bool { return seq%3 == 0 }
	r, mem, _ := runV2Primary(t, n, func(r *rig) Engine { return failingEngine{Engine: V1(r.rs), fail: fails} })
	checkV2Serves(t, r, mem, n)
	if got := testutil.ToFloat64(r.m.ShadowFailures.WithLabelValues("v1")); got == 0 {
		t.Fatal("no v1 shadow failure counted")
	}
	for _, ev := range topicVerdicts(t, mem, TopicVerdictsV1) {
		if fails(ev.Seq) {
			t.Fatalf("seq %d: a failed oracle wrote a record", ev.Seq)
		}
	}
}

func TestNoRolloutWhenV2Serves(t *testing.T) {
	r := newRig(t, newMemory(), nil)
	slot := NewSlot(V2(r.rs), r.m)
	if err := slot.StoreWithShadow(V2(r.rs), V1(r.rs)); err != nil {
		t.Fatal(err)
	}
	if err := slot.SetRollout(1); err == nil {
		t.Fatal("a rollout would hand rules back to v1")
	}
	if err := slot.SetRollout(0); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(r.m.RolloutPercent); got != 100 {
		t.Fatalf("rollout gauge %v, want 100", got)
	}
	// Back to v1 serving (a restart without -serve v2 in production), the
	// gauge reads the rollout again.
	if err := slot.StoreWithShadow(V1(r.rs), V2(r.rs)); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(r.m.RolloutPercent); got != 0 {
		t.Fatalf("rollout gauge %v after v1 serves again, want 0", got)
	}
}
