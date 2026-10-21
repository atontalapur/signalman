package loadtest

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	repoRules    = "../../rules"
	repoTaxonomy = "../../config/taxonomy"
)

func repoSet(t testing.TB) (*sigma.RuleSet, *sigma.Taxonomy) {
	t.Helper()
	tax, err := sigma.LoadTaxonomy(repoTaxonomy)
	if err != nil {
		t.Fatal(err)
	}
	rs, errs, err := sigma.LoadRuleSet(repoRules, tax)
	if err != nil || len(errs) != 0 {
		t.Fatal(err, errs)
	}
	return rs, tax
}

func repoCorpus(t testing.TB, rs *sigma.RuleSet, tax *sigma.Taxonomy) *Corpus {
	t.Helper()
	c, err := FromRules(rs, tax, 20, 1)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newHarness(t testing.TB, rs *sigma.RuleSet, tax *sigma.Taxonomy, mutate func(*Config)) *Harness {
	t.Helper()
	cfg := Config{Rules: rs, Taxonomy: tax, MaxPoll: 50, SampleEvery: 10 * time.Millisecond}
	cfg.Pipe = DefaultPipe()
	cfg.Pipe.QueueSize, cfg.Pipe.RetryBackoff, cfg.Pipe.SampleInterval = 64, 5*time.Millisecond, 5*time.Millisecond
	if mutate != nil {
		mutate(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}

func TestFromRulesIsDeterministicAndDropFree(t *testing.T) {
	rs, tax := repoSet(t)
	a, b := repoCorpus(t, rs, tax), repoCorpus(t, rs, tax)
	if len(a.Records) != len(b.Records) || len(a.Records) == 0 {
		t.Fatalf("%d and %d records", len(a.Records), len(b.Records))
	}
	for i := range a.Records {
		if !bytes.Equal(a.Records[i].Value, b.Records[i].Value) || !bytes.Equal(a.Records[i].Key, b.Records[i].Key) {
			t.Fatalf("record %d differs between two generations with one seed", i)
		}
	}
	if n := a.Drops(tax); n != 0 {
		t.Fatalf("%d generated records would be dropped; FromRules must exclude them", n)
	}
	r := a.Records[0]
	if r.Topic != pipe.TopicEventsRaw || string(r.Header(pipe.HeaderSource)) != SourceLoadgen || len(r.Key) == 0 {
		t.Fatalf("record shape %+v", r)
	}
	t.Logf("%d records, %d excluded", len(a.Records), a.Excluded)
}

func TestReadNDJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("b.ndjson", `{"host_id":"h1","source":"auditd","event_time":1}`+"\n\n"+`not json`+"\n")
	write("sub/a.jsonl", `{"event_time":2}`+"\n")
	write("notes.txt", `{"ignored":true}`)
	c, err := ReadNDJSON(dir, "sysmon")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Records) != 3 {
		t.Fatalf("%d records, want 3 (sorted paths, blank lines skipped, bad lines kept)", len(c.Records))
	}
	if string(c.Records[0].Key) != "h1" || string(c.Records[0].Header(pipe.HeaderSource)) != "auditd" {
		t.Fatalf("host and source from the line: %+v", c.Records[0])
	}
	if string(c.Records[1].Value) != "not json" || string(c.Records[1].Header(pipe.HeaderSource)) != "sysmon" {
		t.Fatalf("unparseable line kept with the default source: %+v", c.Records[1])
	}
	if !bytes.Contains(c.Records[2].Value, []byte(`"event_time":2`)) {
		t.Fatalf("sub/a.jsonl read last: %s", c.Records[2].Value)
	}
}

func TestInject(t *testing.T) {
	c := tinyCorpus(6)
	x := []broker.Record{rawRecord("p", "s", []byte("X")), rawRecord("p", "s", []byte("Y"))}
	got := c.Inject(2, x)
	var s string
	for _, r := range got.Records {
		s += string(r.Value)
	}
	if s != "abXcdYefX" {
		t.Fatalf("injected stream %q", s)
	}
	if len(c.Records) != 6 {
		t.Fatal("Inject modified its receiver")
	}
}

func TestHarnessAccountsForEveryEvent(t *testing.T) {
	rs, tax := repoSet(t)
	h := newHarness(t, rs, tax, nil)
	c := repoCorpus(t, rs, tax)
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	st, err := h.Replay(context.Background(), c, ReplayConfig{Phases: []Phase{{Rate: 4000, For: 750 * time.Millisecond}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WaitCommitted(context.Background(), 20*time.Second); err != nil {
		t.Fatal(err)
	}
	got := h.Check()
	if !got.OK() || got.Events != st.Sent || got.Evaluated != st.Sent || got.Dropped != 0 {
		t.Fatalf("sent %d, correctness %+v", st.Sent, got)
	}
	if got.Matched == 0 {
		t.Fatal("an aimed corpus produced no matches; the digest comparison would be vacuous")
	}
	if got.SlowParses != 0 {
		t.Fatalf("%d verdict records missed the fast parse", got.SlowParses)
	}
	ref, err := h.ReferenceDigests(context.Background(), pipe.V1(rs))
	if err != nil {
		t.Fatal(err)
	}
	assertDigests(t, got.Digests, ref)
	lat := Summarize(h.Tap.Latencies(), 0, 0)
	if lat.N != st.Sent || lat.P99 <= 0 {
		t.Fatalf("latency %+v for %d events", lat, st.Sent)
	}
}

func assertDigests(t testing.TB, got, want map[int32]string) {
	t.Helper()
	if len(got) != len(want) || len(want) == 0 {
		t.Fatalf("digests over %d partitions, reference over %d", len(got), len(want))
	}
	for p, w := range want {
		if got[p] != w {
			t.Fatalf("partition %d digest %s, reference %s", p, got[p], w)
		}
	}
}

func TestKillAfterDurableOutputsRedeliversAndTheDigestHolds(t *testing.T) {
	rs, tax := repoSet(t)
	h := newHarness(t, rs, tax, nil)
	c := repoCorpus(t, rs, tax)
	if err := h.Preload(c, 3000); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		killed := h.KillAfterOutputs(5)
		if err := h.Start(); err != nil {
			t.Fatal(err)
		}
		if err := <-killed; err != nil {
			t.Fatal(err)
		}
	}
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.WaitCommitted(context.Background(), 20*time.Second); err != nil {
		t.Fatal(err)
	}
	got := h.Check()
	if !got.OK() || got.Missing != 0 || got.Evaluated != 3000 {
		t.Fatalf("correctness %+v", got)
	}
	if got.DuplicateVerdictRecords == 0 {
		t.Fatal("a kill after durable outputs and before the commit must redeliver that batch")
	}
	ref, err := h.ReferenceDigests(context.Background(), pipe.V1(rs))
	if err != nil {
		t.Fatal(err)
	}
	assertDigests(t, got.Digests, ref)
}

func TestTapCountsAStraddleAndAShortVerdictList(t *testing.T) {
	rs, _ := repoSet(t)
	alt := *rs
	alt.Rules = rs.Rules[:len(rs.Rules)-1]
	alt.Version = "alt"
	mem := broker.NewMemory(map[string]int32{pipe.TopicEventsRaw: 1})
	tap := NewTap(mem, 1, 4)
	defer tap.Close()
	tap.Expect(rs)
	tap.Expect(&alt)

	item := func(seq uint64, e pipe.Engine) *pipe.Item {
		ev := &event.Event{Seq: seq, Fields: map[string]event.Value{}}
		it := &pipe.Item{Rec: broker.Record{Topic: pipe.TopicEventsRaw, Offset: int64(seq)}, Event: ev}
		it.Verdicts = e.EvaluateInto(nil, ev)
		return it
	}
	full, part := pipe.V1(rs), pipe.V1(&alt)
	a, b := item(0, full), item(1, part)
	if err := tap.Produce(context.Background(), []broker.Record{
		pipe.NormRecord(a), pipe.VerdictRecord(full, a), pipe.NormRecord(b), pipe.VerdictRecord(part, b),
	}); err != nil {
		t.Fatal(err)
	}
	short := item(2, full)
	short.Verdicts = short.Verdicts[:3]
	if err := tap.Produce(context.Background(), []broker.Record{pipe.NormRecord(short), pipe.VerdictRecord(full, short)}); err != nil {
		t.Fatal(err)
	}
	got := tap.Check(map[int32]int64{0: 3})
	if got.Straddles != 1 || got.ShortVerdicts != 1 || got.Missing != 1 || got.OK() {
		t.Fatalf("correctness %+v", got)
	}
}

func TestOfflinePartitionHoldsOnlyItself(t *testing.T) {
	rs, tax := repoSet(t)
	h := newHarness(t, rs, tax, func(c *Config) { c.Partitions = 4 })
	c := repoCorpus(t, rs, tax)
	h.Tap.SetOffline(0, true)
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	if err := h.Preload(c, 2000); err != nil {
		t.Fatal(err)
	}
	end := h.Produced()
	deadline := time.Now().Add(20 * time.Second)
	for {
		com := h.Committed()
		if com[1] == end[1] && com[2] == end[2] && com[3] == end[3] {
			if com[0] != 0 {
				t.Fatalf("offline partition 0 committed %d", com[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("online partitions did not finish while 0 was offline: %v of %v", com, end)
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.Tap.SetOffline(0, false)
	if _, err := h.WaitCommitted(context.Background(), 20*time.Second); err != nil {
		t.Fatal(err)
	}
	got := h.Check()
	if !got.OK() || got.Evaluated != 2000 {
		t.Fatalf("correctness %+v", got)
	}
	ref, err := h.ReferenceDigests(context.Background(), pipe.V1(rs))
	if err != nil {
		t.Fatal(err)
	}
	assertDigests(t, got.Digests, ref)
}

func TestOutputOutageIsLagNotLoss(t *testing.T) {
	rs, tax := repoSet(t)
	h := newHarness(t, rs, tax, nil)
	c := repoCorpus(t, rs, tax)
	h.Tap.SetOutage(true)
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	if err := h.Preload(c, 1500); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if com := sum(h.Committed()); com != 0 {
		t.Fatalf("%d committed during the outage", com)
	}
	if h.Tap.OutageErrors() == 0 {
		t.Fatal("the sink never tried to write during the outage")
	}
	h.Tap.SetOutage(false)
	if _, err := h.WaitCommitted(context.Background(), 20*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := h.Check(); !got.OK() || got.Evaluated != 1500 || got.Dropped != 0 {
		t.Fatalf("correctness %+v", got)
	}
}

func TestPoisonRecordIsOneDropAndThePartitionMovesOn(t *testing.T) {
	rs, tax := repoSet(t)
	h := newHarness(t, rs, tax, nil)
	h.SetFault(PoisonFault)
	c := repoCorpus(t, rs, tax).Inject(100, []broker.Record{PoisonRecord("host-07")})
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	n := len(c.Records)
	if err := h.Preload(c, n); err != nil {
		t.Fatal(err)
	}
	if _, err := h.WaitCommitted(context.Background(), 20*time.Second); err != nil {
		t.Fatal(err)
	}
	got := h.Check()
	poisons := n / 101
	if !got.OK() || got.Dropped != poisons || got.DropReasons[pipe.ReasonPanic] != poisons || got.Evaluated != n-poisons {
		t.Fatalf("%d records with %d poison, correctness %+v", n, poisons, got)
	}
}

func TestCorrectnessIsJSON(t *testing.T) {
	b, err := json.Marshal(Correctness{Digests: map[int32]string{0: "x"}})
	if err != nil || !bytes.Contains(b, []byte(`"digests":{"0":"x"}`)) {
		t.Fatalf("%s %v", b, err)
	}
}

func TestMalformedRecordsEachDropForTheirReason(t *testing.T) {
	_, tax := repoSet(t)
	norm := pipe.NewNormalizer(tax, pipe.NormalizeConfig{}, obs.New(prometheus.NewRegistry()))
	in := pipe.NewIngest(obs.New(prometheus.NewRegistry()))
	recs := MalformedRecords("h")
	if len(recs) != 7 {
		t.Fatalf("%d malformed records, want one per decode reason", len(recs))
	}
	for reason, r := range recs {
		it := in.Admit(r)
		norm.Normalize(it)
		if it.Drop == nil || it.Drop.Reason != reason {
			t.Fatalf("%s record dropped as %+v", reason, it.Drop)
		}
	}
}

func TestTapCountsARedeliveryWhoseBytesChanged(t *testing.T) {
	rs, _ := repoSet(t)
	mem := broker.NewMemory(map[string]int32{pipe.TopicEventsRaw: 1})
	tap := NewTap(mem, 1, 4)
	defer tap.Close()
	tap.Expect(rs)

	ev := &event.Event{Seq: 0, Fields: map[string]event.Value{}}
	it := &pipe.Item{Rec: broker.Record{Topic: pipe.TopicEventsRaw, Offset: 0}, Event: ev}
	e := pipe.V1(rs)
	it.Verdicts = e.EvaluateInto(nil, ev)
	first := pipe.VerdictRecord(e, it)
	if err := tap.Produce(context.Background(), []broker.Record{pipe.NormRecord(it), first}); err != nil {
		t.Fatal(err)
	}
	// The same rule set and the same matched rules, but different bytes:
	// a redelivery that compares equal on indices alone.
	again := first
	again.Value = bytes.Replace(first.Value, []byte(`"taxonomy_v":"`), []byte(`"taxonomy_v":"x`), 1)
	if bytes.Equal(again.Value, first.Value) {
		t.Fatal("test record did not change")
	}
	if err := tap.Produce(context.Background(), []broker.Record{pipe.NormRecord(it), again}); err != nil {
		t.Fatal(err)
	}
	got := tap.Check(map[int32]int64{0: 1})
	if got.RedeliveryChanged != 1 || got.DuplicateVerdictRecords != 0 {
		t.Fatalf("redelivery changed %d, duplicates %d; want 1 and 0", got.RedeliveryChanged, got.DuplicateVerdictRecords)
	}
	if got.OK() {
		t.Fatal("OK() with a redelivered verdict record that changed")
	}
	if !got.OKAcrossReloads() {
		t.Fatalf("OKAcrossReloads() false: %+v", got)
	}
}

func TestTapCountsAnIdenticalRedeliveryAsADuplicate(t *testing.T) {
	rs, _ := repoSet(t)
	mem := broker.NewMemory(map[string]int32{pipe.TopicEventsRaw: 1})
	tap := NewTap(mem, 1, 4)
	defer tap.Close()
	tap.Expect(rs)
	ev := &event.Event{Seq: 0, Fields: map[string]event.Value{}}
	it := &pipe.Item{Rec: broker.Record{Topic: pipe.TopicEventsRaw, Offset: 0}, Event: ev}
	e := pipe.V1(rs)
	it.Verdicts = e.EvaluateInto(nil, ev)
	for range 2 {
		if err := tap.Produce(context.Background(), []broker.Record{pipe.NormRecord(it), pipe.VerdictRecord(e, it)}); err != nil {
			t.Fatal(err)
		}
	}
	got := tap.Check(map[int32]int64{0: 1})
	if got.RedeliveryChanged != 0 || got.DuplicateVerdictRecords != 1 || !got.OK() {
		t.Fatalf("correctness %+v", got)
	}
}

func TestTapCountsSendsThatWaitForTheCheckingPool(t *testing.T) {
	mem := broker.NewMemory(map[string]int32{pipe.TopicEventsRaw: 1})
	tap := NewTap(mem, 1, 1)
	defer tap.Close()
	rec := []broker.Record{{Topic: pipe.TopicDrops, Value: []byte(`{}`)}}
	if err := tap.Produce(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	tap.Flush()
	if n := tap.Blocked(); n != 0 {
		t.Fatalf("blocked %d with an idle pool", n)
	}
	// Hold the worker: process takes tap.mu. With a queue of one, the
	// third call at the latest has to wait for the pool.
	tap.mu.Lock()
	done := make(chan error, 1)
	go func() {
		for range 3 {
			if err := tap.Produce(context.Background(), rec); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	deadline := time.Now().Add(5 * time.Second)
	for tap.Blocked() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	tap.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := tap.Blocked(); n < 1 {
		t.Fatalf("blocked %d; a send that waited for a full queue was not counted", n)
	}
}
