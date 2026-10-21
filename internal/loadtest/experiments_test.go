package loadtest

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/pipe"
)

// The seven experiments of spec phase 05, in process over the in-memory
// broker:
//
//	SIGNALMAN_LOAD=1 go test -run 'TestLoadExperiment/<name>' -v -timeout 2h ./internal/loadtest/
//
// Names: sustained-2x, sustained-5x, consumer-kill, poison-record,
// reload-under-load, sink-unavailable, partition-offline. Each writes one
// report (SIGNALMAN_LOAD_OUT) answering the phase's three questions: where
// work queued (stage depths, broker lag), what fell behind first (the
// order the stage queues filled), and what happened to correctness (drop
// ledger, invariant 1, the verdict digest against a replay).
//
// Phase durations are the in-process defaults below, times
// SIGNALMAN_LOAD_SCALE. The spec's are 30 minutes and 10 minutes; the
// in-memory broker keeps every events.raw record, so the in-process runs
// are minutes, and the long runs belong on Redpanda.

// ExperimentReport is one experiment's evidence.
type ExperimentReport struct {
	Name     string      `json:"name"`
	Env      Environment `json:"env"`
	Pipe     string      `json:"pipe"`
	Baseline float64     `json:"baseline_rate"`
	Phases   []Phase     `json:"phases"`
	Replay   ReplayStats `json:"replay"`
	Marks    []Mark      `json:"marks"`
	// LoadThroughput is the committed rate while load was offered, after
	// the first five seconds.
	LoadThroughput float64      `json:"load_throughput"`
	Saturations    []Saturation `json:"saturations"`
	PeakLag        LagPoint     `json:"peak_lag"`
	LagCurve       []LagPoint   `json:"lag_curve"`
	// Drain is from the end of the offered load to the last commit.
	Drain       time.Duration `json:"drain_ns"`
	LoadLatency Latency       `json:"load_latency"`
	AllLatency  Latency       `json:"all_latency"`
	Resources   Resources     `json:"resources"`
	Correctness Correctness   `json:"correctness"`
	// DigestsMatchReplay is whether the deduplicated output digests equal
	// a clean replay of events.raw through v1; nil where a replay is not
	// comparable (a run that mixes rule sets).
	DigestsMatchReplay *bool          `json:"digests_match_replay"`
	Extra              map[string]any `json:"extra,omitempty"`
}

var wall WallClock

// experiment is one shared setup.
type experiment struct {
	t    *testing.T
	set  loadRuleSet
	c    *Corpus
	base float64
	h    *Harness
	rep  *ExperimentReport
	t0   time.Duration // load start
	t1   time.Duration // load end
	// reloads is set by an experiment that swaps rule sets, where a
	// redelivered event may legitimately be evaluated under the other one.
	reloads bool
}

func newExperiment(t *testing.T, name string, set loadRuleSet, c *Corpus, base float64) *experiment {
	t.Helper()
	cfg := loadConfig(set)
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return &experiment{t: t, set: set, c: c, base: base, h: h, rep: &ExperimentReport{
		Name: name, Env: environment(set), Pipe: pipeString(cfg), Baseline: base, Extra: map[string]any{},
	}}
}

func (e *experiment) phase(mult float64, d time.Duration) Phase {
	return Phase{Rate: mult * e.base, For: scaled(d)}
}

// run starts the consumer, replays the phases while during runs alongside,
// and waits for the backlog to drain.
func (e *experiment) run(phases []Phase, during func(ctx context.Context)) {
	e.t.Helper()
	if !e.h.Running() {
		if err := e.h.Start(); err != nil {
			e.t.Fatal(err)
		}
	}
	e.rep.Phases = phases
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	if during != nil {
		go func() { defer close(done); during(ctx) }()
	} else {
		close(done)
	}
	e.t0 = e.h.Since()
	e.h.Mark("load-start")
	st, err := e.h.Replay(context.Background(), e.c, ReplayConfig{Phases: phases})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t1 = e.h.Since()
	e.h.Mark("load-end")
	e.rep.Replay = st
	cancel()
	<-done
	if !e.h.Running() {
		if err := e.h.Start(); err != nil {
			e.t.Fatal(err)
		}
	}
	drain, err := e.h.WaitCommitted(context.Background(), scaled(time.Hour))
	if err != nil {
		e.t.Fatal(err)
	}
	e.rep.Drain = drain
	e.h.Mark("drained")
}

// finish fills in the report from the samples and outputs, compares the
// digests with a clean replay when compare is set, and writes it.
func (e *experiment) finish(compare bool) *ExperimentReport {
	e.t.Helper()
	ck := e.h.Check()
	ss := e.h.Samples()
	cfg := e.h.Config()
	lat := e.h.Tap.Latencies()
	r := e.rep
	r.Marks = e.h.Marks()
	r.LoadThroughput = Throughput(ss, e.t0+5*time.Second, e.t1)
	r.Saturations = Saturations(ss, cfg.Pipe.QueueSize, cfg.Pipe.MaxInflightBatches)
	r.PeakLag = PeakLag(ss)
	r.LagCurve = LagCurve(ss, scaled(10*time.Second))
	r.LoadLatency = Summarize(lat, e.t0+5*time.Second, e.t1)
	r.AllLatency = Summarize(lat, 0, 0)
	r.Resources = ResourcesOf(ss)
	r.Correctness = ck
	if compare {
		ref, err := e.h.ReferenceDigests(context.Background(), pipe.V1(e.set.rs))
		if err != nil {
			e.t.Fatal(err)
		}
		ok := len(ref) == len(ck.Digests) && len(ref) > 0
		for p, d := range ref {
			ok = ok && ck.Digests[p] == d
		}
		r.DigestsMatchReplay = &ok
	}
	writeReport(e.t, "experiment-"+r.Name+"-"+e.set.name, r)
	e.t.Logf("%s: sent %d, evaluated %d, dropped %d, missing %d, dup verdict records %d, straddles %d, peak lag %d at %v, drain %v, load p99 %v, digests match replay %v",
		r.Name, r.Replay.Sent, ck.Evaluated, ck.Dropped, ck.Missing, ck.DuplicateVerdictRecords, ck.Straddles,
		r.PeakLag.Lag, r.PeakLag.At.Round(time.Millisecond), r.Drain.Round(time.Millisecond), r.LoadLatency.P99, deref(r.DigestsMatchReplay))
	ok := ck.OK()
	if e.reloads {
		ok = ck.OKAcrossReloads()
	}
	if !ok {
		e.t.Errorf("%s: invariant 1, the reload contract, or redelivery identity failed: %+v", r.Name, ck)
	}
	return r
}

func deref(b *bool) any {
	if b == nil {
		return "n/a"
	}
	return *b
}

// windowCommitted is how far each partition's commit moved between two
// instants.
func windowCommitted(ss []Sample, from, to time.Duration) []int64 {
	var a, b *Sample
	for i := range ss {
		if a == nil && ss[i].At >= from {
			a = &ss[i]
		}
		if ss[i].At <= to {
			b = &ss[i]
		}
	}
	if a == nil || b == nil {
		return nil
	}
	out := make([]int64, len(a.PartCommitted))
	for p := range out {
		out[p] = b.PartCommitted[p] - a.PartCommitted[p]
	}
	return out
}

func maxDepthBetween(ss []Sample, from, to time.Duration) [numStages]float64 {
	var m [numStages]float64
	for _, s := range ss {
		if s.At >= from && s.At <= to {
			for i := range m {
				m[i] = max(m[i], s.Depth[i])
			}
		}
	}
	return m
}

func TestLoadExperiment(t *testing.T) {
	requireLoad(t)
	set := loadRules(t)
	c := loadCorpus(t, set)
	base := measureBaseline(t, set, c).Rate
	t.Logf("baseline %.0f events/s on %s (%d rules)", base, set.name, len(set.rs.Rules))

	t.Run("sustained-2x", func(t *testing.T) {
		e := newExperiment(t, "sustained-2x", set, c, base)
		e.run([]Phase{e.phase(2, 2*time.Minute)}, nil)
		r := e.finish(true)
		if r.Correctness.Dropped != 0 {
			t.Fatalf("2x sustained wrote %d drop ledger entries; overload must be lag, never loss", r.Correctness.Dropped)
		}
		if r.DigestsMatchReplay == nil || !*r.DigestsMatchReplay {
			t.Fatal("2x sustained: output digests differ from a clean replay")
		}
	})

	t.Run("sustained-5x", func(t *testing.T) {
		e := newExperiment(t, "sustained-5x", set, c, base)
		e.run([]Phase{e.phase(5, time.Minute)}, nil)
		r := e.finish(true)
		if r.Correctness.Dropped != 0 {
			t.Fatalf("5x sustained wrote %d drop ledger entries", r.Correctness.Dropped)
		}
		if r.DigestsMatchReplay == nil || !*r.DigestsMatchReplay {
			t.Fatal("5x sustained: output digests differ from a clean replay")
		}
	})

	t.Run("consumer-kill", func(t *testing.T) {
		e := newExperiment(t, "consumer-kill", set, c, base)
		const kills = 5
		var killedAt []time.Duration
		e.run([]Phase{e.phase(0.8, time.Minute)}, func(ctx context.Context) {
			for k := range kills {
				if !wall.Sleep(ctx, scaled(10*time.Second)) {
					return
				}
				// Kill on the (k+3)-th batch from now: after its outputs are
				// durable, before its offsets are committed.
				ch := e.h.KillAfterOutputs(3 + k)
				select {
				case err := <-ch:
					if err != nil {
						t.Errorf("kill %d: %v", k, err)
					}
				case <-ctx.Done():
					// The load ended first. Disarm; a kill already under way
					// finishes within the second, and run restarts after it.
					e.h.Tap.AfterOutputs(nil)
					select {
					case <-ch:
					case <-time.After(time.Second):
					}
					return
				}
				killedAt = append(killedAt, e.h.Since())
				e.h.Mark(fmt.Sprintf("kill-%d", k+1))
				time.Sleep(2 * time.Second)
				if err := e.h.Start(); err != nil {
					t.Errorf("restart %d: %v", k, err)
				}
				e.h.Mark(fmt.Sprintf("restart-%d", k+1))
			}
		})
		r := e.finish(true)
		r.Extra["kills"] = len(killedAt)
		if r.Correctness.DuplicateVerdictRecords == 0 {
			t.Fatal("no redelivery after kills that land between durable outputs and the commit")
		}
		if r.DigestsMatchReplay == nil || !*r.DigestsMatchReplay {
			t.Fatal("consumer kill: the digest after recovery differs from a clean replay")
		}
		writeReport(t, "experiment-"+r.Name+"-"+set.name, r)
	})

	t.Run("poison-record", func(t *testing.T) {
		e := newExperiment(t, "poison-record", set, c, base)
		e.h.SetFault(PoisonFault)
		bad := []broker.Record{PoisonRecord("host-05")}
		mal := MalformedRecords("host-05")
		reasons := make([]string, 0, len(mal))
		for k := range mal {
			reasons = append(reasons, k)
		}
		sort.Strings(reasons)
		for _, k := range reasons {
			bad = append(bad, mal[k])
		}
		// One bad record in every 500 (or every tenth of a small corpus),
		// cycling through the poison record and one of each decode
		// failure, all on one host and so one partition.
		e.c = c.Inject(max(1, min(500, len(c.Records)/10)), bad)
		e.run([]Phase{e.phase(0.8, time.Minute)}, nil)
		r := e.finish(true)
		want := map[string]int{}
		for i := range r.Replay.Sent {
			rec := e.c.Records[i%len(e.c.Records)]
			if string(rec.Key) == "host-05" && isBad(rec, bad) {
				want[reasonOf(rec, mal)]++
			}
		}
		r.Extra["expected_drops"] = want
		// Latency on the partition the bad records land in, against the
		// rest: a wedged partition would show here first.
		host05 := keyPartition(t, e.h, "host-05")
		var on, off []LatencySample
		for _, l := range e.h.Tap.Latencies() {
			if l.Partition == host05 {
				on = append(on, l)
			} else {
				off = append(off, l)
			}
		}
		r.Extra["bad_partition"] = host05
		r.Extra["bad_partition_latency"] = Summarize(on, e.t0+5*time.Second, e.t1)
		r.Extra["other_partitions_latency"] = Summarize(off, e.t0+5*time.Second, e.t1)
		total := 0
		for _, n := range want {
			total += n
		}
		if total == 0 || r.Correctness.Dropped != total {
			t.Errorf("%d drops for %d bad records sent", r.Correctness.Dropped, total)
		}
		for reason, n := range want {
			if r.Correctness.DropReasons[reason] != n {
				t.Errorf("%s: %d drops, %d bad records sent", reason, r.Correctness.DropReasons[reason], n)
			}
		}
		if r.DigestsMatchReplay == nil || !*r.DigestsMatchReplay {
			t.Error("poison record: digests differ from a clean replay")
		}
		writeReport(t, "experiment-"+r.Name+"-"+set.name, r)
	})

	t.Run("reload-under-load", func(t *testing.T) {
		e := newExperiment(t, "reload-under-load", set, c, base)
		alt := *set.rs
		alt.Rules = set.rs.Rules[:len(set.rs.Rules)-len(set.rs.Rules)/10]
		alt.Version = set.rs.Version + "-minus-10pct"
		e.h.Tap.Expect(&alt)
		e.reloads = true
		reloads := 0
		e.run([]Phase{e.phase(0.8, time.Minute)}, func(ctx context.Context) {
			for i := 0; ; i++ {
				if !wall.Sleep(ctx, 250*time.Millisecond) {
					return
				}
				if i%2 == 0 {
					e.h.Store(&alt)
				} else {
					e.h.Store(set.rs)
				}
				reloads++
			}
		})
		r := e.finish(false)
		r.Extra["reloads"] = reloads
		if r.Correctness.Straddles != 0 {
			t.Fatalf("%d batches straddled two rule set versions", r.Correctness.Straddles)
		}
		if len(r.Correctness.EventsByVersion) != 2 {
			t.Fatalf("events by version %v; the reloads never took effect", r.Correctness.EventsByVersion)
		}
		writeReport(t, "experiment-"+r.Name+"-"+set.name, r)
	})

	t.Run("sink-unavailable", func(t *testing.T) {
		e := newExperiment(t, "sink-unavailable", set, c, base)
		down, up := scaled(20*time.Second), scaled(50*time.Second)
		var downAt, upAt time.Duration
		e.run([]Phase{e.phase(0.8, 90*time.Second)}, func(ctx context.Context) {
			if !wall.Sleep(ctx, down) {
				return
			}
			e.h.Tap.SetOutage(true)
			downAt = e.h.Since()
			e.h.Mark("outage-start")
			if !wall.Sleep(ctx, up-down) {
				return
			}
			e.h.Tap.SetOutage(false)
			upAt = e.h.Since()
			e.h.Mark("outage-end")
		})
		ss := e.h.Samples()
		r := e.finish(true)
		r.Extra["outage_errors"] = e.h.Tap.OutageErrors()
		r.Extra["max_depth_during_outage"] = maxDepthBetween(ss, downAt, upAt)
		r.Extra["committed_during_outage"] = windowCommitted(ss, downAt+time.Second, upAt)
		var ing0, ing1 float64
		for _, s := range ss {
			if s.At <= downAt+2*time.Second {
				ing0 = s.Ingested
			}
			if s.At <= upAt {
				ing1 = s.Ingested
			}
		}
		r.Extra["admitted_during_outage_after_2s"] = ing1 - ing0
		// Recovery: first sample after the outage with lag back at its
		// pre-outage level.
		var pre int64
		for _, s := range ss {
			if s.At <= downAt {
				pre = s.Produced - s.Committed
			}
		}
		for _, s := range ss {
			if s.At > upAt && s.Produced-s.Committed <= max(pre, int64(2*e.h.Config().MaxPoll)) {
				r.Extra["recovered_after_ns"] = s.At - upAt
				break
			}
		}
		if r.DigestsMatchReplay == nil || !*r.DigestsMatchReplay {
			t.Fatal("sink outage: alerts did not survive; digests differ from a clean replay")
		}
		writeReport(t, "experiment-"+r.Name+"-"+set.name, r)
	})

	t.Run("partition-offline", func(t *testing.T) {
		e := newExperiment(t, "partition-offline", set, c, base)
		const dead = int32(3)
		down, up := scaled(15*time.Second), scaled(45*time.Second)
		var downAt, upAt time.Duration
		e.run([]Phase{e.phase(0.8, time.Minute)}, func(ctx context.Context) {
			if !wall.Sleep(ctx, down) {
				return
			}
			e.h.Tap.SetOffline(dead, true)
			downAt = e.h.Since()
			e.h.Mark("partition-offline")
			if !wall.Sleep(ctx, up-down) {
				return
			}
			e.h.Tap.SetOffline(dead, false)
			upAt = e.h.Since()
			e.h.Mark("partition-online")
		})
		ss := e.h.Samples()
		r := e.finish(true)
		during := windowCommitted(ss, downAt+2*time.Second, upAt)
		r.Extra["offline_partition"] = dead
		r.Extra["committed_per_partition_during_outage"] = during
		r.Extra["outage_latency"] = Summarize(e.h.Tap.Latencies(), downAt+2*time.Second, upAt)
		for p, n := range during {
			if int32(p) != dead && n == 0 {
				t.Errorf("partition %d made no progress while %d was offline", p, dead)
			}
		}
		if len(during) > int(dead) && during[dead] != 0 {
			t.Errorf("offline partition %d committed %d records", dead, during[dead])
		}
		// No consumer restarts, so nothing is redelivered: a withheld fetch
		// must not cost a duplicate.
		if ck := r.Correctness; ck.DuplicateVerdictRecords != 0 || ck.DuplicateAlerts != 0 || ck.DuplicateDrops != 0 {
			t.Errorf("partition offline: %d duplicate verdict records, %d duplicate alerts, %d duplicate drops; want none",
				ck.DuplicateVerdictRecords, ck.DuplicateAlerts, ck.DuplicateDrops)
		}
		if r.DigestsMatchReplay == nil || !*r.DigestsMatchReplay {
			t.Fatal("partition offline: digests differ from a clean replay")
		}
		writeReport(t, "experiment-"+r.Name+"-"+set.name, r)
	})
}

// keyPartition is where the broker put records keyed host.
func keyPartition(t *testing.T, h *Harness, host string) int32 {
	t.Helper()
	for p := int32(0); p < h.Config().Partitions; p++ {
		r, err := h.Mem.ReadFrom(map[broker.TopicPartition]int64{{Topic: pipe.TopicEventsRaw, Partition: p}: 0})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		f, err := r.Poll(ctx)
		cancel()
		r.Close()
		if err != nil {
			continue
		}
		for _, rec := range f.Records {
			if string(rec.Key) == host {
				return p
			}
		}
	}
	t.Fatalf("no partition holds host %s", host)
	return -1
}

func isBad(rec broker.Record, bad []broker.Record) bool {
	for _, b := range bad {
		if string(b.Value) == string(rec.Value) && len(b.Headers) == len(rec.Headers) {
			return true
		}
	}
	return false
}

func reasonOf(rec broker.Record, mal map[string]broker.Record) string {
	for k, m := range mal {
		if string(m.Value) == string(rec.Value) && len(m.Headers) == len(rec.Headers) {
			return k
		}
	}
	return pipe.ReasonPanic
}
