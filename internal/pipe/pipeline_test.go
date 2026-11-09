package pipe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newPipeline(t testing.TB, r *rig, cfg Config) *Pipeline {
	t.Helper()
	p, err := New(cfg, r.b, r.norm, NewSlot(V1(r.rs), r.m), r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPipelineEveryEventLeavesAsVerdictsOrADrop(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	const n = 300
	produceRaw(t, mem, 0, n)
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)

	raw := readAll(t, mem, TopicEventsRaw)
	outs := outcomes(t, mem)
	wantDrops := 0
	for _, rec := range raw {
		o := outs[rec.Partition][uint64(rec.Offset)]
		if o == nil {
			t.Fatalf("partition %d seq %d left no trace", rec.Partition, rec.Offset)
		}
		if (o.verdicts == 0) == (o.drops == 0) {
			t.Fatalf("partition %d seq %d: %d verdict records and %d drops; exactly one kind is allowed", rec.Partition, rec.Offset, o.verdicts, o.drops)
		}
		if o.drops > 0 {
			wantDrops++
		}
	}
	if wantDrops != n/7 {
		t.Fatalf("%d drops, generator makes %d", wantDrops, n/7)
	}
	norm := readAll(t, mem, TopicEventsNorm)
	if len(norm) != n-wantDrops {
		t.Fatalf("%d events.norm records for %d normalized events", len(norm), n-wantDrops)
	}
	for _, rec := range readAll(t, mem, TopicVerdictsV1) {
		var ev EventVerdicts
		if err := json.Unmarshal(rec.Value, &ev); err != nil {
			t.Fatal(err)
		}
		if len(ev.Verdicts) != len(r.rs.Rules) {
			t.Fatalf("seq %d has %d verdicts for %d rules", ev.Seq, len(ev.Verdicts), len(r.rs.Rules))
		}
		if rec.Partition != ev.Partition || string(rec.Key) != strconv.Itoa(int(ev.Partition)) {
			t.Fatal("verdicts are pinned to and keyed by the event's partition")
		}
		if ev.Engine != "v1" || ev.RuleSetV != r.rs.Version || ev.TaxonomyV != r.rs.TaxonomyV {
			t.Fatalf("verdict stream identity %+v", ev)
		}
	}
	if got := testutil.ToFloat64(r.m.EventsDropped.WithLabelValues(ReasonNestedValue, "sysmon")); got != float64(wantDrops) {
		t.Fatalf("dropped counter = %v", got)
	}
}

func TestPipelineVerdictsArriveInSeqOrderPerPartition(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(7))
	r := newRig(t, mem, mem)
	produceRaw(t, mem, 0, 200)
	cfg := testConfig()
	cfg.NormalizeWorkers, cfg.MatchWorkers = 8, 8
	runUntilCommitted(t, newPipeline(t, r, cfg), mem)

	last := map[int32]uint64{}
	seen := map[int32]bool{}
	for _, rec := range readAll(t, mem, TopicVerdictsV1) {
		var ev EventVerdicts
		_ = json.Unmarshal(rec.Value, &ev)
		if seen[ev.Partition] && ev.Seq <= last[ev.Partition] {
			t.Fatalf("partition %d: seq %d after %d; workers may finish out of order but the sink may not write out of order", ev.Partition, ev.Seq, last[ev.Partition])
		}
		seen[ev.Partition], last[ev.Partition] = true, ev.Seq
	}
}

func TestPipelineCommitsOnlyWhatIsDurable(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(5))
	g := &gated{Broker: mem, failNext: 3}
	r := newRig(t, g, mem)
	produceRaw(t, mem, 0, 120)

	var violations []string
	prev := map[broker.TopicPartition]int64{}
	g.onCommit = func(next map[broker.TopicPartition]int64) {
		// Read straight from the backing broker: everything below the
		// offset about to be committed must already have its outcome.
		outs := outcomes(t, mem)
		for tp, off := range next {
			for s := prev[tp]; s < off; s++ {
				if o := outs[tp.Partition][uint64(s)]; o == nil {
					violations = append(violations, fmt.Sprintf("commit of %s/%d to %d before seq %d was durable", tp.Topic, tp.Partition, off, s))
				}
			}
			prev[tp] = off
		}
	}
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)
	for _, v := range violations {
		t.Error(v)
	}
	if g.calls < 4 {
		t.Fatalf("the injected failures were never retried: %d produce calls", g.calls)
	}
}

// With the pipeline stalled, ingest blocks on a full queue and stops
// polling, so no poll reports new high watermarks. The lag gauge must still
// count records produced during the stall; otherwise it freezes exactly
// when the backlog grows. Found by code review after the sink's version of
// the same freeze (docs/load.md, "ClickHouse unavailable").
func TestPipelineLagGrowsWhileStalled(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(4))
	g := &gated{Broker: mem, hold: make(chan struct{})}
	r := newRig(t, g, mem)
	gen := func(from, n int) []broker.Record {
		var recs []broker.Record
		for i := from; len(recs) < n; i++ {
			if i%7 != 6 {
				recs = append(recs, genRaw(i))
			}
		}
		return recs
	}
	if err := mem.Produce(context.Background(), gen(0, 200)); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.LagRefreshInterval = time.Millisecond
	p := newPipeline(t, r, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- p.Run(ctx) }()

	lag := func() float64 {
		var sum float64
		for part := 0; part < testPartitions; part++ {
			sum += testutil.ToFloat64(r.m.ConsumerLag.WithLabelValues(TopicEventsRaw, strconv.Itoa(part)))
		}
		return sum
	}
	deadline := time.Now().Add(5 * time.Second)
	for lag() < 200 {
		if time.Now().After(deadline) {
			t.Fatalf("lag %v before the extra records; want the 200 already produced", lag())
		}
		time.Sleep(time.Millisecond)
	}
	if err := mem.Produce(context.Background(), gen(1000, 300)); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for lag() != 500 {
		if time.Now().After(deadline) {
			t.Fatalf("lag %v while stalled; want 500, the 300 produced during the stall included", lag())
		}
		time.Sleep(time.Millisecond)
	}
	close(g.hold)
	cancel()
	<-errc
}

func TestPipelineLagsInsteadOfDropping(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(4))
	g := &gated{Broker: mem, hold: make(chan struct{})}
	r := newRig(t, g, mem)
	// Only well-formed records, so any drop at all is a backpressure drop.
	var recs []broker.Record
	for i := 0; len(recs) < 400; i++ {
		if i%7 != 6 {
			recs = append(recs, genRaw(i))
		}
	}
	n := len(recs)
	if err := mem.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	p := newPipeline(t, r, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- p.Run(ctx) }()

	// The sink is stuck. Wait for the stages to fill, then check that the
	// consumer stopped: what it has admitted is bounded by the channels,
	// not by the backlog.
	// One batch in the sink, MaxInflightBatches queued, one blocked in
	// ingest on the full queue: each is one poll of at most 4 records. The
	// stage channels hold items of those batches, so they add nothing.
	bound := float64((cfg.MaxInflightBatches + 2) * 4)
	var ingested float64
	for i := 0; i < 200; i++ {
		ingested = total(r.m.EventsIngested)
		time.Sleep(2 * time.Millisecond)
	}
	t.Logf("admitted %v of %d records with the sink stuck (bound %v)", ingested, n, bound)
	if ingested == 0 || ingested > bound {
		t.Fatalf("admitted %v records with the sink stuck; the bound is %v", ingested, bound)
	}
	if ingested >= float64(n) {
		t.Fatal("a stuck sink must stop the consumer, not let it read the whole backlog")
	}
	if d := total(r.m.EventsDropped); d != 0 {
		t.Fatalf("%v events dropped under backpressure; lag over loss", d)
	}
	for _, stage := range []string{StageNormalize, StageMatch, StageSink} {
		depth := testutil.ToFloat64(r.m.StageQueueDepth.WithLabelValues(stage))
		if depth > float64(cfg.QueueSize) {
			t.Fatalf("stage %s depth %v exceeds its bound %d", stage, depth, cfg.QueueSize)
		}
	}
	lag := 0.0
	for part := 0; part < testPartitions; part++ {
		lag += testutil.ToFloat64(r.m.ConsumerLag.WithLabelValues(TopicEventsRaw, strconv.Itoa(part)))
	}
	if lag < float64(n)-bound {
		t.Fatalf("consumer lag %v with %v of %d records admitted and none committed", lag, ingested, n)
	}

	close(g.hold)
	deadline := time.After(20 * time.Second)
	for {
		if done, _ := committedAll(mem); done {
			break
		}
		select {
		case <-deadline:
			t.Fatal("pipeline did not recover once the sink was released")
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	<-errc
	if d := total(r.m.EventsDropped); d != 0 {
		t.Fatalf("after recovery %v drops, want none", d)
	}
	for part := 0; part < testPartitions; part++ {
		if lag := testutil.ToFloat64(r.m.ConsumerLag.WithLabelValues(TopicEventsRaw, strconv.Itoa(part))); lag != 0 {
			t.Fatalf("partition %d lag %v after catching up", part, lag)
		}
	}
}

func TestPipelineRestartRedeliversWhatWasNotCommitted(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(6))
	r := newRig(t, mem, mem)
	produceRaw(t, mem, 0, 100)
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)

	// Kill the next run while its sink is stuck, so batches are in flight
	// and uncommitted.
	produceRaw(t, mem, 100, 100)
	g := &gated{Broker: mem, hold: make(chan struct{})}
	r2 := newRig(t, g, mem)
	p2 := newPipeline(t, r2, testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- p2.Run(ctx) }()
	for total(r2.m.EventsIngested) == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-errc
	if done, _ := committedAll(mem); done {
		t.Fatal("nothing should have committed while the sink was stuck")
	}

	r3 := newRig(t, mem, mem)
	runUntilCommitted(t, newPipeline(t, r3, testConfig()), mem)
	outs := outcomes(t, mem)
	for _, rec := range readAll(t, mem, TopicEventsRaw) {
		if outs[rec.Partition][uint64(rec.Offset)] == nil {
			t.Fatalf("partition %d seq %d was lost across the restart", rec.Partition, rec.Offset)
		}
	}
}

func TestPoisonRecordInThePipelineDoesNotWedgeItsPartition(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(3))
	r := newRig(t, mem, mem)
	real := r.norm.decode
	r.norm.decode = func(raw []byte) (map[string]event.Value, *Drop) {
		if bytes.Contains(raw, []byte("poison")) {
			var none []byte
			_ = none[len(raw)]
		}
		return real(raw)
	}
	poison := rawRecord("host-x", "sysmon", `{"event_time":1,"x":"poison"}`)
	if err := mem.Produce(context.Background(), []broker.Record{poison}); err != nil {
		t.Fatal(err)
	}
	var after []broker.Record
	for i := 0; i < 20; i++ {
		after = append(after, rawRecord("host-x", "sysmon", `{"event_time":1}`))
	}
	if err := mem.Produce(context.Background(), after); err != nil {
		t.Fatal(err)
	}
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)

	drops := readAll(t, mem, TopicDrops)
	if len(drops) != 1 {
		t.Fatalf("%d drops, want the one poison record", len(drops))
	}
	var d DropEntry
	_ = json.Unmarshal(drops[0].Value, &d)
	if d.Reason != ReasonPanic || !bytes.Equal(d.Raw, poison.Value) {
		t.Fatalf("drop entry %+v", d)
	}
	if got := len(readAll(t, mem, TopicVerdictsV1)); got != 20 {
		t.Fatalf("%d verdict records after the poison record, want 20", got)
	}
}

func TestConfigWorkerPoolsAreConfiguredNotComputed(t *testing.T) {
	mem := newMemory()
	r := newRig(t, mem, mem)
	for _, mutate := range []func(*Config){
		func(c *Config) { c.NormalizeWorkers = 0 },
		func(c *Config) { c.MatchWorkers = 0 },
		func(c *Config) { c.QueueSize = 0 },
		func(c *Config) { c.MaxInflightBatches = 0 },
		func(c *Config) { c.Group = "" },
	} {
		cfg := testConfig()
		mutate(&cfg)
		if _, err := New(cfg, r.b, r.norm, NewSlot(V1(r.rs), r.m), r.m, nil); err == nil {
			t.Fatalf("config %+v accepted; sizes are stated, never defaulted from the machine", cfg)
		}
	}
}

func TestPipelineUnknownOrInvalidSourceIsOneDropEach(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	body := `{"event_time":1}`
	// A source header that is not UTF-8 used to reach a Prometheus label,
	// which panics the ingest goroutine on every redelivery.
	bad := []broker.Record{
		rawRecord("host-1", "sys\xffmon", body),
		rawRecord("host-1", "never-seen-before", body),
	}
	if err := mem.Produce(context.Background(), bad); err != nil {
		t.Fatal(err)
	}
	produceRaw(t, mem, 0, 20)
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)

	outs := outcomes(t, mem)
	for _, rec := range readAll(t, mem, TopicEventsRaw) {
		o := outs[rec.Partition][uint64(rec.Offset)]
		if o == nil || (o.verdicts == 0) == (o.drops == 0) {
			t.Fatalf("partition %d seq %d: %+v; exactly one outcome is allowed", rec.Partition, rec.Offset, o)
		}
	}
	got := 0
	for _, rec := range readAll(t, mem, TopicDrops) {
		var d DropEntry
		if err := json.Unmarshal(rec.Value, &d); err != nil {
			t.Fatal(err)
		}
		if d.Reason == ReasonUnknownSource {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("%d unknown-source drops, want 2", got)
	}
	if v := testutil.ToFloat64(r.m.EventsDropped.WithLabelValues(ReasonUnknownSource, SourceOther)); v != 2 {
		t.Fatalf("dropped{reason=%s,source=%s} = %v", ReasonUnknownSource, SourceOther, v)
	}
	part := strconv.Itoa(int(readAll(t, mem, TopicEventsRaw)[0].Partition))
	for _, rec := range readAll(t, mem, TopicEventsRaw) {
		if string(rec.Key) == "host-1" {
			part = strconv.Itoa(int(rec.Partition))
		}
	}
	if v := testutil.ToFloat64(r.m.EventsIngested.WithLabelValues(SourceOther, part)); v != 2 {
		t.Fatalf("ingested{source=%s} = %v; a header outside the known set is not a label", SourceOther, v)
	}
}
