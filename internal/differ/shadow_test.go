package differ

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const dumpRuleID = "1f1a1f1a-0001-4000-8000-000000000001"

// pipeline is signalmand in process over mem: v1 serving, shadow beside it.
func runPipeline(t *testing.T, mem *broker.Memory, shadow func(*sigma.RuleSet) pipe.Engine, n int) *sigma.RuleSet {
	t.Helper()
	tax, err := sigma.LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	rs, errs, err := sigma.LoadRuleSet("../engine/v1/testdata/rules", tax)
	if err != nil || len(errs) != 0 {
		t.Fatal(err, errs)
	}
	m := obs.New(prometheus.NewRegistry())
	slot := pipe.NewSlot(pipe.V1(rs), m)
	if err := slot.StoreWithShadow(pipe.V1(rs), shadow(rs)); err != nil {
		t.Fatal(err)
	}
	p, err := pipe.New(pipe.Config{Group: "signalmand", NormalizeWorkers: 2, MatchWorkers: 3, QueueSize: 8, MaxInflightBatches: 2},
		mem, pipe.NewNormalizer(tax, pipe.NormalizeConfig{}, m), slot, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	recs := make([]broker.Record, n)
	for i := range recs {
		cmd := "cmd.exe /c whoami"
		if i%3 == 0 {
			cmd = "rundll32.exe comsvcs.dll, MiniDump 624 C:\\t.dmp full"
		}
		body, _ := json.Marshal(map[string]any{
			"Channel": "Microsoft-Windows-Sysmon/Operational", "event_id": 1,
			"Image": `C:\Windows\System32\rundll32.exe`, "CommandLine": cmd,
			"event_time": int64(1790000000000 + i),
		})
		recs[i] = broker.Record{Topic: pipe.TopicEventsRaw, Partition: broker.AnyPartition,
			Key: fmt.Appendf(nil, "host-%d", i%7), Value: body, Headers: []broker.Header{{Key: pipe.HeaderSource, Value: []byte("sysmon")}}}
	}
	if err := mem.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- p.Run(ctx) }()
	deadline := time.After(20 * time.Second)
	for {
		end, _ := mem.EndOffsets(ctx, pipe.TopicEventsRaw)
		c, _ := mem.CommittedOffsets(ctx, "signalmand", pipe.TopicEventsRaw)
		done := true
		for p, e := range end {
			done = done && c[p] == e
		}
		if done {
			break
		}
		select {
		case err := <-errc:
			t.Fatalf("pipeline stopped: %v", err)
		case <-deadline:
			t.Fatal("pipeline did not commit everything")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-errc
	return rs
}

// faultyV2 is v2 with injected bugs: the dump rule's verdict flipped on
// every fourth seq, and a panic on seqs that are 4 mod 9.
type faultyV2 struct{ pipe.Engine }

func (f faultyV2) EvaluateInto(dst []event.Verdict, ev *event.Event) []event.Verdict {
	if ev.Seq%9 == 4 {
		panic("injected")
	}
	out := f.Engine.EvaluateInto(dst, ev)
	if ev.Seq%4 == 0 {
		for i := range out {
			if out[i].RuleID == dumpRuleID {
				out[i].Matched = !out[i].Matched
			}
		}
	}
	return out
}

func TestShadowLaneWithIdenticalEnginesHasNoDivergences(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(13))
	runPipeline(t, mem, pipe.V2, 400)
	v1n := len(readAll(t, mem, pipe.TopicVerdictsV1))
	if v1n != 400 || len(readAll(t, mem, pipe.TopicVerdictsV2)) != 400 {
		t.Fatal("every event has a v1 and a v2 record")
	}
	r := start(t, mem, testConfig())
	r.waitFor(t, "every event compared", func() bool { return r.joined() == float64(v1n) })
	r.stop(t)
	if d := divergences(t, mem); len(d) != 0 {
		t.Fatalf("v2 and v1 diverged %d times: %+v", len(d), d[0])
	}
}

func TestShadowLaneWithAFaultyEngineReportsEachClass(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(13))
	runPipeline(t, mem, func(rs *sigma.RuleSet) pipe.Engine { return faultyV2{pipe.V2(rs)} }, 400)

	// What the differ must report, from v1's own records. The last seq on
	// a partition with no v2 record stays unresolved until a later v2
	// record arrives, so it is not expected yet.
	recs := readAll(t, mem, pipe.TopicVerdictsV1)
	last := map[int32]uint64{}
	for _, rec := range recs {
		var ev pipe.EventVerdicts
		_ = json.Unmarshal(rec.Value, &ev)
		last[ev.Partition] = max(last[ev.Partition], ev.Seq)
	}
	want := map[Class]int{}
	for _, rec := range recs {
		var ev pipe.EventVerdicts
		if err := json.Unmarshal(rec.Value, &ev); err != nil {
			t.Fatal(err)
		}
		switch {
		case ev.Seq%9 == 4:
			if ev.Seq != last[ev.Partition] {
				want[ClassMissing] += len(ev.Verdicts)
			}
		case ev.Seq%4 == 0:
			for _, v := range ev.Verdicts {
				if v.RuleID == dumpRuleID && v.Matched {
					want[ClassFalseNegative]++
				} else if v.RuleID == dumpRuleID {
					want[ClassFalsePositive]++
				}
			}
		}
	}
	for _, c := range []Class{ClassFalseNegative, ClassFalsePositive, ClassMissing} {
		if want[c] == 0 {
			t.Fatalf("no %s injected; the test proves nothing", c)
		}
	}
	total := want[ClassFalseNegative] + want[ClassFalsePositive] + want[ClassMissing]

	r := start(t, mem, testConfig())
	r.waitFor(t, "every injected divergence", func() bool { return testutil.ToFloat64(r.m.Counted) >= float64(total) })
	time.Sleep(20 * time.Millisecond)
	r.stop(t)
	got := map[Class]int{}
	for _, d := range divergences(t, mem) {
		got[d.Class]++
		if d.Class == ClassMissing && (d.Missing != "v2" || d.V2 != nil || d.V1 == nil) {
			t.Fatalf("a v2 panic is a missing v2 verdict: %+v", d)
		}
		if d.Class != ClassMissing && d.RuleID != dumpRuleID {
			t.Fatalf("only the dump rule was flipped: %+v", d)
		}
	}
	for _, c := range Classes {
		if got[c] != want[c] {
			t.Fatalf("%s: %d divergences, want %d (all: %v)", c, got[c], want[c], got)
		}
	}
}
