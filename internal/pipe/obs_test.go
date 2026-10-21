package pipe

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

func itoa(p int32) string { return strconv.Itoa(int(p)) }

func histCount(t *testing.T, r *rig, ruleID string) uint64 {
	t.Helper()
	var pb dto.Metric
	h, err := r.m.RuleEval.GetMetricWithLabelValues(ruleID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.(interface{ Write(*dto.Metric) error }).Write(&pb); err != nil {
		t.Fatal(err)
	}
	return pb.GetHistogram().GetSampleCount()
}

// Staleness is set from event times once a batch is durable, and is read
// against the metrics clock, not anything the engine sees.
func TestStalenessFollowsTheNewestDurableEventTimePerPartition(t *testing.T) {
	now := time.UnixMilli(1790000000000 + 60_000)
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRigClock(t, mem, mem, func() time.Time { return now })
	produceRaw(t, mem, 0, 200)
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)

	newest := map[int32]time.Time{}
	for _, rec := range readAll(t, mem, TopicEventsNorm) {
		var n NormEvent
		if err := json.Unmarshal(rec.Value, &n); err != nil {
			t.Fatal(err)
		}
		if n.EventTime.After(newest[n.Partition]) {
			newest[n.Partition] = n.EventTime
		}
	}
	if len(newest) == 0 {
		t.Fatal("no normalized events")
	}
	for p, et := range newest {
		got, ok := r.m.Staleness.Age(p)
		if !ok || got != now.Sub(et) {
			t.Fatalf("partition %d staleness %v (tracked %v), want %v", p, got, ok, now.Sub(et))
		}
	}
	// Nothing new arrives; lag is zero and staleness keeps rising.
	now = now.Add(5 * time.Minute)
	for p, et := range newest {
		if lag := testutil.ToFloat64(r.m.ConsumerLag.WithLabelValues(TopicEventsRaw, itoa(p))); lag != 0 {
			t.Fatalf("partition %d lag %v after everything committed", p, lag)
		}
		if got, _ := r.m.Staleness.Age(p); got != now.Sub(et) {
			t.Fatalf("partition %d staleness %v after 5m of silence, want %v", p, got, now.Sub(et))
		}
	}
}

func TestRuleEvalSecondsIsSampledPerRule(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	const n, every = 100, 10
	produceRaw(t, mem, 0, n)
	cfg := testConfig()
	cfg.RuleEvalEvery = every
	runUntilCommitted(t, newPipeline(t, r, cfg), mem)

	// Sampling is by seq, per partition, over evaluated events only.
	sampled := 0
	for _, rec := range readAll(t, mem, TopicVerdictsV1) {
		var ev EventVerdicts
		if err := json.Unmarshal(rec.Value, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Seq%every == 0 {
			sampled++
		}
	}
	if sampled == 0 {
		t.Fatal("generator produced no sampled events; pick another stride")
	}
	if got := testutil.CollectAndCount(r.m.RuleEval); got != len(r.rs.Rules) {
		t.Fatalf("%d rule_eval series, want one per rule (%d)", got, len(r.rs.Rules))
	}
	for _, rule := range r.rs.Rules {
		if c := histCount(t, r, rule.ID); c != uint64(sampled) {
			t.Fatalf("rule %s observed %d times, want %d sampled events", rule.ID, c, sampled)
		}
	}
}

func TestRuleEvalSamplingOffByDefault(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	produceRaw(t, mem, 0, 50)
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)
	if got := testutil.CollectAndCount(r.m.RuleEval); got != 0 {
		t.Fatalf("%d rule_eval series with sampling off", got)
	}
}
