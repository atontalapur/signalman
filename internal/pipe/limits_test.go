package pipe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNormalizeDropsARecordOverTheSizeLimit(t *testing.T) {
	// Every value is under MaxValueLen; the record as a whole is not.
	v := strings.Repeat("a", 50<<10)
	body := `{"event_time":1,"a":"` + v + `","b":"` + v + `","c":"` + v + `"}`
	n, m := newNormalizer(t)
	it := item("sysmon", body)
	n.Normalize(it)
	if it.Drop == nil || it.Drop.Reason != ReasonRecordTooLarge {
		t.Fatalf("drop = %+v, want %s", it.Drop, ReasonRecordTooLarge)
	}
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues(ReasonRecordTooLarge, "sysmon")); got != 1 {
		t.Fatalf("dropped counter = %v", got)
	}
}

// size is what a broker counts against max.message.bytes for one record.
func size(r broker.Record) int { return broker.RecordSize(r) }

func TestEveryDropEntryFitsTheOutputLimit(t *testing.T) {
	limit := DefaultMaxRecordBytes
	// '<' escapes to six bytes in JSON, the worst case for a string field.
	cases := map[string]broker.Record{
		"key at the limit": {Topic: TopicEventsRaw, Key: []byte(strings.Repeat("<", limit-20)), Value: []byte("x"),
			Headers: []broker.Header{{Key: HeaderSource, Value: []byte("sysmon")}}},
		"source at the limit": {Topic: TopicEventsRaw, Key: []byte("h"), Value: []byte("x"),
			Headers: []broker.Header{{Key: HeaderSource, Value: []byte(strings.Repeat("<", limit-20))}}},
		"value at the limit": {Topic: TopicEventsRaw, Key: []byte("h"), Value: bytes.Repeat([]byte("<"), limit-20),
			Headers: []broker.Header{{Key: HeaderSource, Value: []byte("sysmon")}}},
		"far over the limit": {Topic: TopicEventsRaw, Key: []byte(strings.Repeat("<", broker.MaxMessageBytes/2)), Value: bytes.Repeat([]byte("<"), broker.MaxMessageBytes/2),
			Headers: []broker.Header{{Key: HeaderSource, Value: []byte(strings.Repeat("<", broker.MaxMessageBytes/2))}}},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			n, _ := newNormalizer(t)
			it := NewIngest(n.m).Admit(r)
			n.Normalize(it)
			if it.Drop == nil {
				t.Fatal("not dropped")
			}
			it.Drop.Detail = strings.Repeat("<", 1<<20) // a detail of any length is cut
			rec := DropRecord(it)
			if s := size(rec); s > MaxOutputRecordBytes {
				t.Fatalf("drop record is %d bytes, over the %d output limit", s, MaxOutputRecordBytes)
			}
			var d DropEntry
			if err := json.Unmarshal(rec.Value, &d); err != nil {
				t.Fatal(err)
			}
			if d.RawBytes != len(r.Value) {
				t.Fatalf("raw_bytes = %d, want %d", d.RawBytes, len(r.Value))
			}
			if d.Truncated != (it.Drop.Reason == ReasonRecordTooLarge) {
				t.Fatalf("truncated = %v for reason %s; only an oversized record is cut", d.Truncated, it.Drop.Reason)
			}
			if !d.Truncated && !bytes.Equal(d.Raw, r.Value) {
				t.Fatal("a record under the limit keeps its exact raw bytes")
			}
		})
	}
}

// fanout is a small raw record whose flattened fields are large: every
// child repeats the long parent name.
func fanout() string {
	var sb strings.Builder
	sb.WriteString(`{"event_time": 1, "` + strings.Repeat("p", 20<<10) + `": {`)
	for i := range 60 {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"c%d": %d`, i, i)
	}
	sb.WriteString("}}")
	return sb.String()
}

func TestPipelineOversizedOutputIsADropAndThePartitionMovesOn(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	big := rawRecord("host-1", "sysmon", fanout())
	if err := mem.Produce(context.Background(), []broker.Record{big}); err != nil {
		t.Fatal(err)
	}
	produceRaw(t, mem, 0, 40)
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)

	outs := outcomes(t, mem)
	for _, rec := range readAll(t, mem, TopicEventsRaw) {
		o := outs[rec.Partition][uint64(rec.Offset)]
		if o == nil || (o.verdicts == 0) == (o.drops == 0) {
			t.Fatalf("partition %d seq %d: %+v; exactly one outcome is allowed", rec.Partition, rec.Offset, o)
		}
	}
	found := false
	for _, rec := range readAll(t, mem, TopicDrops) {
		var d DropEntry
		if err := json.Unmarshal(rec.Value, &d); err != nil {
			t.Fatal(err)
		}
		if d.Reason == ReasonOutputTooLarge {
			found = true
			if !bytes.Equal(d.Raw, big.Value) || d.Offset != 0 {
				t.Fatalf("drop entry %+v", d)
			}
		}
	}
	if !found {
		t.Fatal("the oversized event left no output-too-large drop")
	}
	for _, rec := range readAll(t, mem, TopicEventsNorm) {
		if size(rec) > MaxOutputRecordBytes {
			t.Fatalf("events.norm record of %d bytes written", size(rec))
		}
	}
	if got := testutil.ToFloat64(r.m.EventsDropped.WithLabelValues(ReasonOutputTooLarge, "sysmon")); got != 1 {
		t.Fatalf("output-too-large counter = %v", got)
	}
}

func TestPipelineStopsOnAPermanentProduceError(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	g := &gated{Broker: mem, failNext: 1 << 30, failWith: fmt.Errorf("%w: message too large", broker.ErrPermanent)}
	r := newRig(t, g, mem)
	produceRaw(t, mem, 0, 20)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := newPipeline(t, r, testConfig()).Run(ctx)
	if !errors.Is(err, broker.ErrPermanent) {
		t.Fatalf("Run = %v; a produce that cannot succeed stops the pipeline", err)
	}
	if ctx.Err() != nil {
		t.Fatal("the pipeline retried until the test gave up")
	}
	g.mu.Lock()
	calls := g.calls
	g.mu.Unlock()
	if calls != 1 {
		t.Fatalf("%d produce calls; a permanent error is not retried", calls)
	}
	c, _ := mem.CommittedOffsets(context.Background(), "signalmand", TopicEventsRaw)
	if len(c) != 0 {
		t.Fatalf("committed %v; nothing was durable", c)
	}
}

func TestPipelineRefusesTopicsThatCannotHoldItsOutputs(t *testing.T) {
	for name, parts := range map[string]map[string]int32{
		"fewer verdict partitions": {TopicEventsRaw: 4, TopicEventsNorm: 4, TopicVerdictsV1: 2, TopicAlerts: 4, TopicDrops: 4},
		"no drops topic":           {TopicEventsRaw: 4, TopicEventsNorm: 4, TopicVerdictsV1: 4, TopicAlerts: 4},
	} {
		t.Run(name, func(t *testing.T) {
			mem := broker.NewMemory(parts)
			r := newRig(t, mem, mem)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := newPipeline(t, r, testConfig()).Run(ctx)
			if err == nil || ctx.Err() != nil {
				t.Fatalf("Run = %v; a topic layout that wedges the sink is refused at startup", err)
			}
			t.Log(err)
		})
	}
}

// escapeHeavy is a raw record that matches the dump rule and carries two
// string fields of '<', which JSON escapes to six bytes each. host is its
// key; pad is the length of each '<' field.
func escapeHeavy(host string, pad int) broker.Record {
	lt := strings.Repeat("<", pad)
	body := `{"Channel":"Microsoft-Windows-Sysmon/Operational","event_id":1,` +
		`"Image":"C:\\Windows\\System32\\rundll32.exe",` +
		`"CommandLine":"rundll32.exe comsvcs.dll, MiniDump 624 C:\\t.dmp full",` +
		`"event_time":1790000000000,"a":"` + lt + `","b":"` + lt + `"}`
	return rawRecord(host, "sysmon", body)
}

func TestPipelineMatchedEventWithEscapeHeavyFieldsIsAlertedNotDropped(t *testing.T) {
	mem := newMemory(broker.WithMaxPoll(10))
	r := newRig(t, mem, mem)
	// About 123 KB, under the admit cap. Its alert with every field escaped
	// a second time would be over the output limit; its events.norm is not.
	big := escapeHeavy("host-big", 60<<10)
	if size(big) > DefaultMaxRecordBytes {
		t.Fatalf("test record is %d bytes, over the admit cap", size(big))
	}
	if err := mem.Produce(context.Background(), []broker.Record{big}); err != nil {
		t.Fatal(err)
	}
	produceRaw(t, mem, 0, 20)
	runUntilCommitted(t, newPipeline(t, r, testConfig()), mem)

	var part int32 = -1
	for _, rec := range readAll(t, mem, TopicEventsRaw) {
		if string(rec.Key) == "host-big" {
			part = rec.Partition
		}
	}
	o := outcomes(t, mem)[part][0]
	if o == nil || o.verdicts != 1 || o.drops != 0 {
		t.Fatalf("outcome %+v; a matched event is evaluated, never dropped for its alert", o)
	}
	for _, rec := range readAll(t, mem, TopicDrops) {
		var d DropEntry
		if err := json.Unmarshal(rec.Value, &d); err != nil {
			t.Fatal(err)
		}
		if d.Reason == ReasonOutputTooLarge {
			t.Fatalf("output-too-large drop %+v", d)
		}
	}
	found := false
	for _, rec := range readAll(t, mem, TopicAlerts) {
		if size(rec) > MaxOutputRecordBytes {
			t.Fatalf("alert record of %d bytes written", size(rec))
		}
		var a Alert
		if err := json.Unmarshal(rec.Value, &a); err != nil {
			t.Fatal(err)
		}
		if a.Seq == 0 && a.Partition == part && a.HostID == "host-big" {
			found = true
			if !a.FieldsOmitted || len(a.Fields) != 0 || a.Raw != string(big.Value) {
				t.Fatalf("bounded alert: fields_omitted %v, %d fields, raw intact %v", a.FieldsOmitted, len(a.Fields), a.Raw == string(big.Value))
			}
		}
	}
	if !found {
		t.Fatal("the matched event raised no alert")
	}
}

func TestEveryAlertFitsTheOutputLimit(t *testing.T) {
	limit := DefaultMaxRecordBytes
	rs := loadRules(t)
	var rule *sigma.Rule
	for i := range rs.Rules {
		if rs.Rules[i].ID == dumpRuleID {
			rule = &rs.Rules[i]
		}
	}
	// The record uses all of the admit cap, split between the key and two
	// '<' fields, so both the raw and the fields escape at six times.
	cases := map[string]broker.Record{
		"raw at the cap": escapeHeavy("h", (limit-400)/2),
		"key at the cap": escapeHeavy(strings.Repeat("<", limit/2), (limit/2-400)/2),
		"short fields":   escapeHeavy("h", 10),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			n, _ := newNormalizer(t)
			it := NewIngest(n.m).Admit(r)
			n.Normalize(it)
			if it.Drop != nil {
				if it.Drop.Reason == ReasonRecordTooLarge && size(r) > limit {
					t.Skipf("record is %d bytes; not admitted", size(r))
				}
				t.Fatalf("dropped: %+v", it.Drop)
			}
			rec := AlertRecord(rule, it)
			if s := size(rec); s > MaxOutputRecordBytes {
				t.Fatalf("alert record is %d bytes, over the %d output limit", s, MaxOutputRecordBytes)
			}
			var a Alert
			if err := json.Unmarshal(rec.Value, &a); err != nil {
				t.Fatal(err)
			}
			if a.Raw != string(r.Value) {
				t.Fatal("an alert keeps the raw record whole")
			}
			if a.FieldsOmitted == (len(a.Fields) > 0) {
				t.Fatalf("fields_omitted %v with %d fields", a.FieldsOmitted, len(a.Fields))
			}
		})
	}
}
