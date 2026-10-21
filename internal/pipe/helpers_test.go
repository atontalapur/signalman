package pipe

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const testPartitions = 4

func newMemory(opts ...broker.MemoryOption) *broker.Memory {
	topics := map[string]int32{}
	for _, t := range []string{TopicEventsRaw, TopicEventsNorm, TopicVerdictsV1, TopicAlerts, TopicDrops} {
		topics[t] = testPartitions
	}
	return broker.NewMemory(topics, opts...)
}

func loadRules(t testing.TB) *sigma.RuleSet {
	t.Helper()
	rs, errs, err := sigma.LoadRuleSet(rulesDir, loadTaxonomy(t))
	if err != nil || len(errs) != 0 {
		t.Fatal(err, errs)
	}
	return rs
}

// genRaw is the i-th generated raw record. Every seventh record is
// malformed and must become a drop; every third matches the dump rule.
func genRaw(i int) broker.Record {
	host := fmt.Sprintf("host-%d", i%13)
	if i%7 == 6 {
		return rawRecord(host, "sysmon", `{"event_time": 1, "broken": [[1]]}`)
	}
	cmd := "cmd.exe /c whoami"
	if i%3 == 0 {
		cmd = "rundll32.exe comsvcs.dll, MiniDump 624 C:\\t.dmp full"
	}
	b, _ := json.Marshal(map[string]any{
		"Channel":     "Microsoft-Windows-Sysmon/Operational",
		"event_id":    1,
		"Image":       `C:\Windows\System32\rundll32.exe`,
		"CommandLine": cmd,
		"event_time":  int64(1790000000000 + i),
		"n":           i,
	})
	return rawRecord(host, "sysmon", string(b))
}

func produceRaw(t testing.TB, b broker.Broker, from, n int) {
	t.Helper()
	recs := make([]broker.Record, 0, n)
	for i := from; i < from+n; i++ {
		recs = append(recs, genRaw(i))
	}
	if err := b.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
}

func testConfig() Config {
	return Config{
		Group:              "signalmand",
		NormalizeWorkers:   3,
		MatchWorkers:       3,
		QueueSize:          16,
		MaxInflightBatches: 2,
		RetryBackoff:       time.Millisecond,
		SampleInterval:     time.Millisecond,
	}
}

type rig struct {
	b    broker.Broker
	mem  *broker.Memory
	reg  *prometheus.Registry
	m    *obs.Metrics
	norm *Normalizer
	rs   *sigma.RuleSet
}

func newRig(t testing.TB, b broker.Broker, mem *broker.Memory) *rig {
	t.Helper()
	return newRigClock(t, b, mem, time.Now)
}

// newRigClock is newRig with the metrics' age gauges read against now.
func newRigClock(t testing.TB, b broker.Broker, mem *broker.Memory, now func() time.Time) *rig {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := obs.NewWithClock(reg, now)
	return &rig{b: b, mem: mem, reg: reg, m: m, norm: NewNormalizer(loadTaxonomy(t), NormalizeConfig{}, m), rs: loadRules(t)}
}

// readAll returns every record in topic, in partition then offset order.
func readAll(t testing.TB, b broker.Broker, topic string) []broker.Record {
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
		var got int64
		for got < end[p] {
			pctx, cancel := context.WithTimeout(ctx, time.Second)
			f, err := c.Poll(pctx)
			cancel()
			if err != nil {
				t.Fatalf("read %s/%d: %v", topic, p, err)
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

func committedAll(b broker.Broker) (done bool, err error) {
	ctx := context.Background()
	end, err := b.EndOffsets(ctx, TopicEventsRaw)
	if err != nil {
		return false, err
	}
	c, err := b.CommittedOffsets(ctx, "signalmand", TopicEventsRaw)
	if err != nil {
		return false, err
	}
	for p, e := range end {
		if e > 0 && c[p] < e {
			return false, nil
		}
	}
	return true, nil
}

// runUntilCommitted runs p until every events.raw record is committed.
func runUntilCommitted(t testing.TB, p *Pipeline, b broker.Broker) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- p.Run(ctx) }()
	deadline := time.After(20 * time.Second)
	for {
		done, err := committedAll(b)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		select {
		case err := <-errc:
			t.Fatalf("pipeline stopped before committing everything: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for the pipeline to commit everything")
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	if err := <-errc; err != nil && err != context.Canceled {
		t.Fatalf("pipeline: %v", err)
	}
}

// gated wraps a broker so a test can hold, fail, or watch Produce and
// Commit.
type gated struct {
	broker.Broker
	mu       sync.Mutex
	hold     chan struct{} // Produce blocks while this is open
	failNext int
	calls    int
	onCommit func(map[broker.TopicPartition]int64)
}

func (g *gated) Produce(ctx context.Context, recs []broker.Record) error {
	g.mu.Lock()
	g.calls++
	hold := g.hold
	fail := g.failNext > 0
	if fail {
		g.failNext--
	}
	g.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail {
		return fmt.Errorf("injected produce failure")
	}
	return g.Broker.Produce(ctx, recs)
}

func (g *gated) Consume(group string, topics []string) (broker.Consumer, error) {
	c, err := g.Broker.Consume(group, topics)
	if err != nil {
		return nil, err
	}
	return &gatedConsumer{Consumer: c, g: g}, nil
}

type gatedConsumer struct {
	broker.Consumer
	g *gated
}

func (c *gatedConsumer) Commit(ctx context.Context, next map[broker.TopicPartition]int64) error {
	c.g.mu.Lock()
	hook := c.g.onCommit
	c.g.mu.Unlock()
	if hook != nil {
		hook(next)
	}
	return c.Consumer.Commit(ctx, next)
}

// outcomes maps partition and seq to how many verdict and drop records
// carry it.
type outcome struct{ verdicts, drops int }

func outcomes(t testing.TB, b broker.Broker) map[int32]map[uint64]*outcome {
	t.Helper()
	out := map[int32]map[uint64]*outcome{}
	get := func(p int32, s uint64) *outcome {
		if out[p] == nil {
			out[p] = map[uint64]*outcome{}
		}
		if out[p][s] == nil {
			out[p][s] = &outcome{}
		}
		return out[p][s]
	}
	for _, r := range readAll(t, b, TopicVerdictsV1) {
		var ev EventVerdicts
		if err := json.Unmarshal(r.Value, &ev); err != nil {
			t.Fatal(err)
		}
		get(ev.Partition, ev.Seq).verdicts++
	}
	for _, r := range readAll(t, b, TopicDrops) {
		var d DropEntry
		if err := json.Unmarshal(r.Value, &d); err != nil {
			t.Fatal(err)
		}
		get(d.Partition, d.Seq).drops++
	}
	return out
}

// total sums every series of a counter or gauge vector.
func total(c prometheus.Collector) float64 {
	ch := make(chan prometheus.Metric, 64)
	go func() { c.Collect(ch); close(ch) }()
	sum := 0.0
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			panic(err)
		}
		sum += pb.GetCounter().GetValue() + pb.GetGauge().GetValue()
	}
	return sum
}
