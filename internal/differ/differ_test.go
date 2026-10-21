package differ

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const parts = 3

func newMemory(opts ...broker.MemoryOption) *broker.Memory {
	topics := map[string]int32{}
	for _, t := range []string{pipe.TopicEventsRaw, pipe.TopicEventsNorm, pipe.TopicVerdictsV1, pipe.TopicVerdictsV2,
		pipe.TopicAlerts, pipe.TopicDrops, TopicDivergences} {
		topics[t] = parts
	}
	return broker.NewMemory(topics, opts...)
}

func testConfig() Config {
	return Config{Group: "differ", Queue: 4, CommitInterval: 5 * time.Millisecond, RetryBackoff: time.Millisecond}
}

// running is a differ in the background with its metrics and log.
type running struct {
	d      *Differ
	m      *Metrics
	log    *syncBuffer
	cancel context.CancelFunc
	errc   chan error
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func start(t *testing.T, b broker.Broker, cfg Config) *running {
	t.Helper()
	m := NewMetrics(prometheus.NewRegistry())
	buf := &syncBuffer{}
	d, err := New(cfg, b, m, slog.New(slog.NewJSONHandler(buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{d: d, m: m, log: buf, cancel: cancel, errc: make(chan error, 1)}
	go func() { r.errc <- d.Run(ctx) }()
	return r
}

// waitFor polls cond until it holds, failing the test after 10 seconds or
// if the differ stops.
func (r *running) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !cond() {
		select {
		case err := <-r.errc:
			t.Fatalf("differ stopped while waiting for %s: %v", what, err)
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(time.Millisecond):
		}
	}
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	r.cancel()
	if err := <-r.errc; err != nil && err != context.Canceled {
		t.Fatalf("differ: %v", err)
	}
}

func (r *running) joined() float64 { return testutil.ToFloat64(r.m.Events) }

// readAll returns every record in topic, in partition then offset order.
func readAll(t *testing.T, b broker.Broker, topic string) []broker.Record {
	t.Helper()
	ctx := context.Background()
	end, err := b.EndOffsets(ctx, topic)
	if err != nil {
		t.Fatal(err)
	}
	var out []broker.Record
	for p := int32(0); p < int32(len(end)); p++ {
		if end[p] == 0 {
			continue
		}
		c, err := b.ReadFrom(map[broker.TopicPartition]int64{{Topic: topic, Partition: p}: 0})
		if err != nil {
			t.Fatal(err)
		}
		for got := int64(0); got < end[p]; {
			pctx, cancel := context.WithTimeout(ctx, time.Second)
			f, err := c.Poll(pctx)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range f.Records {
				if r.Offset < end[p] {
					out = append(out, r)
					got++
				}
			}
		}
		c.Close()
	}
	return out
}

func divergences(t *testing.T, b broker.Broker) []Divergence {
	t.Helper()
	var out []Divergence
	for _, r := range readAll(t, b, TopicDivergences) {
		var d Divergence
		if err := json.Unmarshal(r.Value, &d); err != nil {
			t.Fatal(err)
		}
		if r.Partition != d.Partition {
			t.Fatalf("divergence for partition %d written to partition %d", d.Partition, r.Partition)
		}
		out = append(out, d)
	}
	return out
}

// verdicts builds a verdict topic record the way the pipeline writes it.
func verdicts(engine string, part int32, seq uint64, rulesetV string, matched ...bool) broker.Record {
	ev := pipe.EventVerdicts{Partition: part, Seq: seq, Engine: engine, RuleSetV: rulesetV, TaxonomyV: "T"}
	if engine == "v1" {
		ev.Shadow = "v2"
	}
	for i, m := range matched {
		ev.Verdicts = append(ev.Verdicts, pipe.RuleVerdict{RuleID: fmt.Sprintf("rule-%d", i), Matched: m})
	}
	b, err := json.Marshal(ev)
	if err != nil {
		panic(err)
	}
	return broker.Record{Topic: "verdicts." + engine, Partition: part, Key: []byte(strconv.Itoa(int(part))), Value: b}
}

func produce(t *testing.T, b broker.Broker, recs ...broker.Record) {
	t.Helper()
	if err := b.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
}

// stream is a deterministic pair of verdict streams over every partition:
// two rules, v1 matching rule-0 on every third seq, and v2 wrong on seqs
// chosen by the caller.
type stream struct {
	n            int
	fn, fp, miss func(seq uint64) bool
}

func (s stream) v1(part int32, seq uint64) broker.Record {
	return verdicts("v1", part, seq, "R", seq%3 == 0, false)
}

func (s stream) v2(part int32, seq uint64) (broker.Record, bool) {
	m0 := seq%3 == 0
	m1 := false
	if s.fn != nil && s.fn(seq) && m0 {
		m0 = false
	}
	if s.fp != nil && s.fp(seq) {
		m1 = true
	}
	return verdicts("v2", part, seq, "R", m0, m1), s.miss == nil || !s.miss(seq)
}

func TestIdenticalStreamsHaveNoDivergences(t *testing.T) {
	mem := newMemory()
	s := stream{n: 200}
	for p := int32(0); p < parts; p++ {
		for seq := uint64(0); seq < uint64(s.n); seq++ {
			v2, _ := s.v2(p, seq)
			produce(t, mem, s.v1(p, seq), v2)
		}
	}
	r := start(t, mem, testConfig())
	r.waitFor(t, "every event joined", func() bool { return r.joined() == parts*200 })
	r.stop(t)
	if d := divergences(t, mem); len(d) != 0 {
		t.Fatalf("%d divergences between identical streams: %+v", len(d), d[0])
	}
	for _, c := range Classes {
		if got := testutil.ToFloat64(r.m.Divergences.WithLabelValues(string(c))); got != 0 {
			t.Fatalf("%s counter = %v", c, got)
		}
	}
}

// expected is what the differ should report for s, per partition, in seq
// order: the differ's output order.
func (s stream) expected() map[int32][]Divergence {
	out := map[int32][]Divergence{}
	for p := int32(0); p < parts; p++ {
		for seq := uint64(0); seq < uint64(s.n); seq++ {
			m0 := seq%3 == 0
			if s.miss != nil && s.miss(seq) {
				out[p] = append(out[p],
					Divergence{Partition: p, Seq: seq, RuleID: "rule-0", Class: ClassMissing, Missing: "v2", V1: side(m0, "R", "T")},
					Divergence{Partition: p, Seq: seq, RuleID: "rule-1", Class: ClassMissing, Missing: "v2", V1: side(false, "R", "T")})
				continue
			}
			if s.fn != nil && s.fn(seq) && m0 {
				out[p] = append(out[p], Divergence{Partition: p, Seq: seq, RuleID: "rule-0", Class: ClassFalseNegative, V1: side(true, "R", "T"), V2: side(false, "R", "T")})
			}
			if s.fp != nil && s.fp(seq) {
				out[p] = append(out[p], Divergence{Partition: p, Seq: seq, RuleID: "rule-1", Class: ClassFalsePositive, V1: side(false, "R", "T"), V2: side(true, "R", "T")})
			}
		}
	}
	return out
}

func byPartition(ds []Divergence) map[int32][]Divergence {
	out := map[int32][]Divergence{}
	for _, d := range ds {
		out[d.Partition] = append(out[d.Partition], d)
	}
	return out
}

func faulty() stream {
	return stream{
		n:    120,
		fn:   func(seq uint64) bool { return seq%9 == 0 },
		fp:   func(seq uint64) bool { return seq%10 == 7 },
		miss: func(seq uint64) bool { return seq%25 == 13 },
	}
}

// writeInterleaved writes s the way the pipeline does: an event's v1 and
// v2 records in one produce, in seq order.
func writeInterleaved(t *testing.T, b broker.Broker, s stream) {
	for p := int32(0); p < parts; p++ {
		for seq := uint64(0); seq < uint64(s.n); seq++ {
			recs := []broker.Record{s.v1(p, seq)}
			if v2, ok := s.v2(p, seq); ok {
				recs = append(recs, v2)
			}
			produce(t, b, recs...)
		}
	}
}

func TestFaultyStreamDivergencesLandInTheirClass(t *testing.T) {
	mem := newMemory()
	s := faulty()
	writeInterleaved(t, mem, s)
	// One extra v1 record, so the differ can resolve the last seq's v2 gap.
	for p := int32(0); p < parts; p++ {
		v2, _ := s.v2(p, uint64(s.n))
		produce(t, mem, s.v1(p, uint64(s.n)), v2)
	}
	r := start(t, mem, testConfig())
	r.waitFor(t, "every event joined", func() bool { return r.joined() == parts*float64(s.n+1) })
	r.stop(t)

	want := s.expected()
	got := byPartition(divergences(t, mem))
	counts := map[Class]int{}
	for p := int32(0); p < parts; p++ {
		if len(got[p]) != len(want[p]) {
			t.Fatalf("partition %d: %d divergences, want %d", p, len(got[p]), len(want[p]))
		}
		for i := range want[p] {
			if !reflect.DeepEqual(got[p][i], want[p][i]) {
				t.Fatalf("partition %d divergence %d:\ngot  %+v\nwant %+v", p, i, got[p][i], want[p][i])
			}
			counts[want[p][i].Class]++
		}
	}
	for _, c := range []Class{ClassFalseNegative, ClassFalsePositive, ClassMissing} {
		if counts[c] == 0 {
			t.Fatalf("no %s injected; the test proves nothing", c)
		}
		if got := testutil.ToFloat64(r.m.Divergences.WithLabelValues(string(c))); got != float64(counts[c]) {
			t.Fatalf("%s counter = %v, want %d", c, got, counts[c])
		}
	}
	// Every divergence is in the structured log too, for the divergence log.
	if n := strings.Count(r.log.String(), `"msg":"divergence"`); n != counts[ClassFalseNegative]+counts[ClassFalsePositive]+counts[ClassMissing] {
		t.Fatalf("%d divergence log lines", n)
	}
	if !strings.Contains(r.log.String(), `"class":"v2_false_negative"`) || !strings.Contains(r.log.String(), `"rule_id":"rule-0"`) {
		t.Fatalf("log lines carry class and rule: %s", r.log.String())
	}
}

func TestVersionSkewIsRecordedButExcluded(t *testing.T) {
	mem := newMemory()
	// Seq 0 agrees; seq 1 disagrees under two RuleSetV values; seq 2
	// disagrees under one RuleSetV and two TaxonomyV values.
	produce(t, mem, verdicts("v1", 0, 0, "R", true), verdicts("v2", 0, 0, "R", true))
	produce(t, mem, verdicts("v1", 0, 1, "R1", true), verdicts("v2", 0, 1, "R2", false))
	tv := verdicts("v2", 0, 2, "R", false)
	tv.Value = bytes.Replace(tv.Value, []byte(`"taxonomy_v":"T"`), []byte(`"taxonomy_v":"T2"`), 1)
	produce(t, mem, verdicts("v1", 0, 2, "R", true), tv)
	r := start(t, mem, testConfig())
	r.waitFor(t, "three events joined", func() bool { return r.joined() == 3 })
	r.stop(t)

	ds := divergences(t, mem)
	if len(ds) != 2 {
		t.Fatalf("%d divergences: %+v", len(ds), ds)
	}
	if ds[0].Seq != 1 || ds[0].Class != ClassVersionSkew || !ds[0].Excluded {
		t.Fatalf("RuleSetV skew: %+v", ds[0])
	}
	if ds[1].Seq != 2 || ds[1].Class != ClassFalseNegative || ds[1].Excluded {
		t.Fatalf("a TaxonomyV difference alone is not skew: %+v", ds[1])
	}
	if got := testutil.ToFloat64(r.m.Divergences.WithLabelValues(string(ClassVersionSkew))); got != 1 {
		t.Fatalf("skew counter = %v", got)
	}
	if got := testutil.ToFloat64(r.m.Counted); got != 1 {
		t.Fatalf("zero-budget divergences counted = %v, want 1: skew is excluded", got)
	}
}

func TestDifferWaitsForTheLaggingSideAndHoldsABoundedWindow(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	const n = 300
	for seq := uint64(0); seq < n; seq++ {
		produce(t, mem, verdicts("v1", 1, seq, "R", seq%2 == 0))
	}
	cfg := testConfig()
	r := start(t, mem, cfg)
	// v2 has written nothing. The differ must neither report v1's records
	// as missing nor read v1 without bound while it waits.
	read := func() float64 { return testutil.ToFloat64(r.m.Read.WithLabelValues("v1")) }
	r.waitFor(t, "the v1 reader to fill its window", func() bool { return read() > 0 })
	prev := -1.0
	for read() != prev {
		prev = read()
		time.Sleep(50 * time.Millisecond)
	}
	// One head held by the joiner, a full channel, and one poll in hand.
	if limit := float64(1 + cfg.Queue + 10); read() > limit {
		t.Fatalf("read %v v1 records ahead of v2; the window is %v", read(), limit)
	}
	if d := divergences(t, mem); len(d) != 0 {
		t.Fatalf("a lagging side was reported as missing: %+v", d[0])
	}
	c, err := mem.CommittedOffsets(context.Background(), cfg.Group, pipe.TopicVerdictsV1)
	if err != nil {
		t.Fatal(err)
	}
	if c[1] != 0 {
		t.Fatalf("committed v1 offset %d before any v1 record was compared", c[1])
	}

	for seq := uint64(0); seq < n; seq++ {
		produce(t, mem, verdicts("v2", 1, seq, "R", seq%2 == 0))
	}
	r.waitFor(t, "the lagging side to catch up", func() bool { return r.joined() == n })
	r.stop(t)
	if d := divergences(t, mem); len(d) != 0 {
		t.Fatalf("%d divergences once v2 caught up: %+v", len(d), d[0])
	}
}

func TestDifferOutputDoesNotDependOnArrivalOrder(t *testing.T) {
	s := faulty()
	// A: the pipeline's own interleaving.
	a := newMemory(broker.WithMaxPoll(7))
	writeInterleaved(t, a, s)

	// B: every v2 record first, partitions in reverse, then v1, with a
	// redelivered prefix on each side the way a retried batch rewrites it.
	b := newMemory(broker.WithMaxPoll(3))
	for p := int32(parts - 1); p >= 0; p-- {
		for seq := uint64(0); seq < uint64(s.n); seq++ {
			if v2, ok := s.v2(p, seq); ok {
				produce(t, b, v2)
			}
			if seq == 50 {
				for again := uint64(40); again <= 50; again++ {
					if v2, ok := s.v2(p, again); ok {
						produce(t, b, v2)
					}
				}
			}
		}
	}
	for p := int32(0); p < parts; p++ {
		for seq := uint64(0); seq < uint64(s.n); seq++ {
			produce(t, b, s.v1(p, seq))
			if seq == 80 {
				for again := uint64(70); again <= 80; again++ {
					produce(t, b, s.v1(p, again))
				}
			}
		}
	}

	out := map[string][]broker.Record{}
	for name, mem := range map[string]*broker.Memory{"a": a, "b": b} {
		// A last pair resolves the final seq on each partition.
		for p := int32(0); p < parts; p++ {
			v2, _ := s.v2(p, uint64(s.n))
			produce(t, mem, s.v1(p, uint64(s.n)), v2)
		}
		r := start(t, mem, testConfig())
		r.waitFor(t, "every event joined", func() bool { return r.joined() == parts*float64(s.n+1) })
		r.stop(t)
		out[name] = readAll(t, mem, TopicDivergences)
	}
	if len(out["a"]) == 0 || len(out["a"]) != len(out["b"]) {
		t.Fatalf("%d and %d divergence records", len(out["a"]), len(out["b"]))
	}
	for i := range out["a"] {
		if out["a"][i].Partition != out["b"][i].Partition || !bytes.Equal(out["a"][i].Value, out["b"][i].Value) {
			t.Fatalf("record %d differs:\n%s\n%s", i, out["a"][i].Value, out["b"][i].Value)
		}
	}
}

func TestDifferResumesFromItsCommittedOffsets(t *testing.T) {
	mem := newMemory()
	s := faulty()
	s.n = 60
	writeInterleaved(t, mem, s)
	for p := int32(0); p < parts; p++ {
		v2, _ := s.v2(p, uint64(s.n))
		produce(t, mem, s.v1(p, uint64(s.n)), v2)
	}
	cfg := testConfig()
	r := start(t, mem, cfg)
	r.waitFor(t, "every event joined", func() bool { return r.joined() == parts*float64(s.n+1) })
	committed := func() bool {
		for _, topic := range []string{pipe.TopicVerdictsV1, pipe.TopicVerdictsV2} {
			end, _ := mem.EndOffsets(context.Background(), topic)
			c, _ := mem.CommittedOffsets(context.Background(), cfg.Group, topic)
			for p, e := range end {
				if c[p] != e {
					return false
				}
			}
		}
		return true
	}
	r.waitFor(t, "offsets committed", committed)
	r.stop(t)
	first := len(divergences(t, mem))

	// A second run over the same topics starts where the first stopped.
	again := start(t, mem, cfg)
	for p := int32(0); p < parts; p++ {
		produce(t, mem, verdicts("v1", p, uint64(s.n+1), "R", true), verdicts("v2", p, uint64(s.n+1), "R", false))
		produce(t, mem, verdicts("v1", p, uint64(s.n+2), "R", false), verdicts("v2", p, uint64(s.n+2), "R", false))
	}
	again.waitFor(t, "the new events joined", func() bool { return again.joined() == 2*parts })
	again.stop(t)
	if got := len(divergences(t, mem)); got != first+parts {
		t.Fatalf("%d divergences after the restart, want %d: one new false negative per partition and no repeats", got, first+parts)
	}
}

func TestUnshadowedRecordsOweNoShadowVerdict(t *testing.T) {
	mem := newMemory()
	for seq := uint64(0); seq < 20; seq++ {
		r := verdicts("v1", 0, seq, "R", true)
		r.Value = bytes.Replace(r.Value, []byte(`,"shadow":"v2"`), nil, 1)
		produce(t, mem, r)
	}
	cfg := testConfig()
	r := start(t, mem, cfg)
	r.waitFor(t, "the unshadowed records consumed", func() bool {
		c, _ := mem.CommittedOffsets(context.Background(), cfg.Group, pipe.TopicVerdictsV1)
		return c[0] == 20
	})
	r.stop(t)
	if d := divergences(t, mem); len(d) != 0 {
		t.Fatalf("an unshadowed v1 record owes no v2 record: %+v", d[0])
	}
}

func TestMissingV1RecordIsADivergence(t *testing.T) {
	mem := newMemory()
	produce(t, mem, verdicts("v2", 0, 0, "R", false))
	produce(t, mem, verdicts("v1", 0, 1, "R", false), verdicts("v2", 0, 1, "R", false))
	r := start(t, mem, testConfig())
	r.waitFor(t, "both seqs resolved", func() bool { return r.joined() == 2 })
	r.stop(t)
	ds := divergences(t, mem)
	if len(ds) != 1 || ds[0].Seq != 0 || ds[0].Class != ClassMissing || ds[0].Missing != "v1" {
		t.Fatalf("divergences %+v", ds)
	}
}

func TestDifferRejectsAMismatchedPartitionCount(t *testing.T) {
	mem := broker.NewMemory(map[string]int32{pipe.TopicVerdictsV1: 2, pipe.TopicVerdictsV2: 3, TopicDivergences: 2})
	d, err := New(testConfig(), mem, NewMetrics(prometheus.NewRegistry()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Run(context.Background()); err == nil {
		t.Fatal("verdict topics with different partition counts cannot be joined on partition")
	}
}
