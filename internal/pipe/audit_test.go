package pipe

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/sigma"
)

// tamper wraps a broker and rewrites what the sink produces, standing in
// for a pipeline bug the audit has to catch.
type tamper struct {
	broker.Broker
	mu      sync.Mutex
	rewrite func([]broker.Record) []broker.Record
}

func (t *tamper) Produce(ctx context.Context, recs []broker.Record) error {
	t.mu.Lock()
	fn := t.rewrite
	t.mu.Unlock()
	if fn != nil {
		recs = fn(recs)
	}
	return t.Broker.Produce(ctx, recs)
}

func auditRig(t *testing.T, b broker.Broker, mem *broker.Memory) (*rig, *Slot, *Auditor) {
	t.Helper()
	r := newRig(t, b, mem)
	slot := NewSlot(V1(r.rs), r.m)
	a, err := NewAuditor(context.Background(), mem, AuditConfig{Group: "signalmand", Window: 25}, slot.RuleCount, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, slot, a
}

func runAndAudit(t *testing.T, r *rig, slot *Slot, a *Auditor, b broker.Broker) ([]WindowReport, error) {
	t.Helper()
	p, err := New(testConfig(), b, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	runUntilCommitted(t, p, r.mem)
	return a.Step(context.Background())
}

func TestAuditIsGreenWhenEveryEventIsAccountedFor(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(8))
	r, slot, a := auditRig(t, mem, mem)
	produceRaw(t, mem, 0, 210)
	reports, err := runAndAudit(t, r, slot, a, mem)
	if err != nil {
		t.Fatal(err)
	}
	var ingested, evaluated, dropped, verdicts int64
	for _, w := range reports {
		if !w.OK() {
			t.Fatalf("window %+v", w)
		}
		if w.To-w.From > 25 {
			t.Fatalf("window %+v is wider than the configured 25", w)
		}
		ingested += w.Ingested
		evaluated += w.Evaluated
		dropped += w.Dropped
		verdicts += w.Verdicts
	}
	if ingested != 210 || dropped != 30 || evaluated != 180 || verdicts != 180*int64(len(r.rs.Rules)) {
		t.Fatalf("ingested %d = evaluated %d + dropped %d, verdicts %d", ingested, evaluated, dropped, verdicts)
	}
	again, err := a.Step(context.Background())
	if err != nil || len(again) != 0 {
		t.Fatalf("a second step with nothing new committed audits nothing: %v %v", again, err)
	}
}

func TestAuditFailsLoudlyOnAMissingVerdictRecord(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(8))
	victim := ""
	tm := &tamper{Broker: mem, rewrite: func(recs []broker.Record) []broker.Record {
		out := recs[:0:0]
		for _, rec := range recs {
			if rec.Topic == TopicVerdictsV1 && victim == "" {
				var ev EventVerdicts
				_ = json.Unmarshal(rec.Value, &ev)
				if ev.Seq == 11 {
					victim = strconv.Itoa(int(ev.Partition))
					continue // the bug: one event's verdicts never written
				}
			}
			out = append(out, rec)
		}
		return out
	}}
	r, slot, a := auditRig(t, tm, mem)
	produceRaw(t, mem, 0, 160)
	reports, err := runAndAudit(t, r, slot, a, tm)
	if victim == "" {
		t.Fatal("the tamper never fired; the test proves nothing")
	}
	if !errors.Is(err, ErrInvariant) {
		t.Fatalf("audit error = %v; one vanished event must fail the audit", err)
	}
	t.Logf("audit: %v", err)
	if !strings.Contains(err.Error(), "partition "+victim) || !strings.Contains(err.Error(), "seq 11") {
		t.Fatalf("the failure names the event: %v", err)
	}
	bad := 0
	for _, w := range reports {
		if !w.OK() {
			bad++
			if w.Missing != 1 || w.Ingested != w.Evaluated+w.Dropped+1 {
				t.Fatalf("window arithmetic %+v", w)
			}
		}
	}
	if bad != 1 {
		t.Fatalf("%d failing windows, want 1", bad)
	}
	if got := total(r.m.AuditViolations); got != 1 {
		t.Fatalf("signalman_audit_violations_total = %v", got)
	}
}

func TestAuditCatchesAShortVerdictList(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(8))
	done := false
	tm := &tamper{Broker: mem, rewrite: func(recs []broker.Record) []broker.Record {
		for i, rec := range recs {
			if rec.Topic == TopicVerdictsV1 && !done {
				var ev EventVerdicts
				_ = json.Unmarshal(rec.Value, &ev)
				ev.Verdicts = ev.Verdicts[1:]
				recs[i].Value, _ = json.Marshal(ev)
				done = true
			}
		}
		return recs
	}}
	r, slot, a := auditRig(t, tm, mem)
	produceRaw(t, mem, 0, 40)
	_, err := runAndAudit(t, r, slot, a, tm)
	if !errors.Is(err, ErrInvariant) || !strings.Contains(err.Error(), "verdicts for") {
		t.Fatalf("audit error = %v; a verdict short of the rule count must fail", err)
	}
}

func TestAuditCatchesAnEventWithBothOutcomes(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(8))
	done := false
	tm := &tamper{Broker: mem, rewrite: func(recs []broker.Record) []broker.Record {
		for _, rec := range recs {
			if rec.Topic == TopicVerdictsV1 && !done {
				var ev EventVerdicts
				_ = json.Unmarshal(rec.Value, &ev)
				d, _ := json.Marshal(DropEntry{Partition: ev.Partition, Seq: ev.Seq, Reason: ReasonParse})
				done = true
				return append(recs, broker.Record{Topic: TopicDrops, Partition: broker.AnyPartition, Value: d})
			}
		}
		return recs
	}}
	r, slot, a := auditRig(t, tm, mem)
	produceRaw(t, mem, 0, 40)
	_, err := runAndAudit(t, r, slot, a, tm)
	if !errors.Is(err, ErrInvariant) || !strings.Contains(err.Error(), "both") {
		t.Fatalf("audit error = %v; verdicts and a drop for one event is not exactly one outcome", err)
	}
}

func TestAuditToleratesRedeliveryDuplicates(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(8))
	r, slot, a := auditRig(t, mem, mem)
	produceRaw(t, mem, 0, 80)
	// Every batch is written twice, as a redelivery after a crash between
	// produce and commit would.
	twice := &tamper{Broker: mem, rewrite: func(recs []broker.Record) []broker.Record {
		return append(append([]broker.Record{}, recs...), recs...)
	}}
	if _, err := runAndAudit(t, r, slot, a, twice); err != nil {
		t.Fatalf("at-least-once duplicates are not a violation: %v", err)
	}
}

func TestAuditRejectsAnUnknownRuleSetVersion(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(8))
	r := newRig(t, mem, mem)
	slot := NewSlot(V1(r.rs), r.m)
	known := func(v string) (int, bool) {
		if v == r.rs.Version {
			return 0, false // pretend the version was never registered
		}
		return slot.RuleCount(v)
	}
	a, err := NewAuditor(context.Background(), mem, AuditConfig{Group: "signalmand"}, known, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	produceRaw(t, mem, 0, 10)
	if _, err := runAndAudit(t, r, slot, a, mem); !errors.Is(err, ErrInvariant) {
		t.Fatalf("verdicts under a version nobody loaded cannot be checked and must fail: %v", err)
	}
}

// TestEndToEndUnderGeneratedLoad is the test-mode stand-in for the Plan C
// gate soak: generated load through the in-memory broker, rule set reloads
// throughout, the audit stepping continuously, and every window green.
//
// It runs for 3 seconds by default. SIGNALMAN_SOAK_DURATION=1h (with
// -timeout 2h) runs it for an hour, but the in-memory broker keeps every
// record, so an hour at the default rate needs several GB of memory. The
// one-hour gate is meant to run against Redpanda; that has not been done.
func TestEndToEndUnderGeneratedLoad(t *testing.T) {
	dur := 3 * time.Second
	if s := os.Getenv("SIGNALMAN_SOAK_DURATION"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
		dur = d
	}
	rate := 5000
	if s := os.Getenv("SIGNALMAN_SOAK_RATE"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		rate = n
	}

	mem := newMemory(broker.WithMaxPoll(64))
	r := newRig(t, mem, mem)
	slot := NewSlot(V1(r.rs), r.m)
	a, err := NewAuditor(context.Background(), mem, AuditConfig{Group: "signalmand", Window: 500}, slot.RuleCount, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.QueueSize, cfg.MaxInflightBatches = 128, 4
	p, err := New(cfg, mem, r.norm, slot, r.m, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- p.Run(ctx) }()

	var (
		produced int
		reports  []WindowReport
		failures []error
	)
	alts := []*sigma.RuleSet{r.rs, subset(r.rs, "soak-alt")}
	tick := 10 * time.Millisecond
	perTick := max(1, rate/100)
	start := time.Now()
	for i := 0; time.Since(start) < dur; i++ {
		produceRaw(t, mem, produced, perTick)
		produced += perTick
		if i%50 == 0 {
			slot.Store(V1(alts[(i/50)%2]))
		}
		if i%10 == 0 {
			ws, err := a.Step(context.Background())
			reports = append(reports, ws...)
			if err != nil {
				failures = append(failures, err)
			}
		}
		time.Sleep(tick)
	}
	deadline := time.After(60 * time.Second)
	for {
		if done, _ := committedAll(mem); done {
			break
		}
		select {
		case <-deadline:
			t.Fatal("pipeline did not drain the generated load")
		case err := <-runErr:
			t.Fatalf("pipeline stopped: %v", err)
		case <-time.After(5 * time.Millisecond):
		}
	}
	ws, err := a.Step(context.Background())
	reports = append(reports, ws...)
	if err != nil {
		failures = append(failures, err)
	}
	cancel()
	<-runErr

	for _, err := range failures {
		t.Error(err)
	}
	var ingested, evaluated, dropped int64
	for _, w := range reports {
		ingested += w.Ingested
		evaluated += w.Evaluated
		dropped += w.Dropped
	}
	if ingested != int64(produced) || evaluated+dropped != ingested {
		t.Fatalf("audited %d of %d produced: %d evaluated + %d dropped", ingested, produced, evaluated, dropped)
	}
	t.Logf("%v of generated load: %d events, %d evaluated, %d dropped, %d audit windows, all green",
		dur, produced, evaluated, dropped, len(reports))
}

func TestAuditStartsAtTheLogStartOfAnUncommittedPartition(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(8))
	produceRaw(t, mem, 0, 120)
	// Retention trimmed the head of every partition before the group ever
	// committed. Those offsets were never admitted, so they are not missing.
	end, _ := mem.EndOffsets(context.Background(), TopicEventsRaw)
	for p, e := range end {
		mem.Trim(broker.TopicPartition{Topic: TopicEventsRaw, Partition: p}, e/2)
	}
	r, slot, a := auditRig(t, mem, mem)
	reports, err := runAndAudit(t, r, slot, a, mem)
	if err != nil {
		t.Fatalf("audit over a trimmed log: %v", err)
	}
	for _, w := range reports {
		if w.From < end[w.Partition]/2 {
			t.Fatalf("window %+v starts below the log start %d", w, end[w.Partition]/2)
		}
	}
	if len(reports) == 0 {
		t.Fatal("nothing audited")
	}
}
