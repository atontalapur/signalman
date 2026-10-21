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

// An event time ahead of the metrics clock advances staleness only to now
// and is counted. Without the clamp one bad clock upstream would pin the
// partition's staleness at zero until the wall clock reached that time.
func TestFutureEventTimeIsClampedForStalenessAndCounted(t *testing.T) {
	now := time.UnixMilli(1790000000000)
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRigClock(t, mem, mem, func() time.Time { return now })
	b, _ := json.Marshal(map[string]any{
		"Channel":     "Microsoft-Windows-Sysmon/Operational",
		"event_id":    1,
		"Image":       `C:\Windows\System32\cmd.exe`,
		"CommandLine": "cmd.exe /c whoami",
		"event_time":  now.Add(24 * time.Hour).UnixMilli(),
	})
	if err := mem.Produce(t.Context(), []broker.Record{rawRecord("host-future", "sysmon", string(b))}); err != nil {
		t.Fatal(err)
	}
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)

	norm := readAll(t, mem, TopicEventsNorm)
	if len(norm) != 1 {
		t.Fatalf("%d normalized events, want 1", len(norm))
	}
	var n NormEvent
	if err := json.Unmarshal(norm[0].Value, &n); err != nil {
		t.Fatal(err)
	}
	p := n.Partition
	now = now.Add(3 * time.Minute)
	if got, ok := r.m.Staleness.Age(p); !ok || got != 3*time.Minute {
		t.Fatalf("partition %d staleness %v (tracked %v) three minutes after a future event, want 3m", p, got, ok)
	}
	if got := testutil.ToFloat64(r.m.EventTimeFuture.WithLabelValues(itoa(p))); got != 1 {
		t.Fatalf("future event time counter %v, want 1", got)
	}
}
