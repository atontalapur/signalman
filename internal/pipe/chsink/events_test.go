package chsink

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/backend/ch"
	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/pipe"
)

// rowTable records every row inserted, in order.
type rowTable struct {
	mu   sync.Mutex
	rows []ch.Row
}

func (t *rowTable) Insert(_ context.Context, rows []ch.Row) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rows = append(t.rows, rows...)
	return nil
}

func (t *rowTable) snapshot() []ch.Row {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]ch.Row(nil), t.rows...)
}

func newEventsBroker() broker.Broker {
	return broker.NewMemory(map[string]int32{pipe.TopicEventsNorm: 3, pipe.TopicEventsDead: 2}, broker.WithMaxPoll(5))
}

func normEvent(p int32, seq uint64) pipe.NormEvent {
	t := time.Date(2026, 11, 1, 12, 0, 0, int(seq)*int(time.Millisecond), time.UTC)
	return pipe.NormEvent{
		Seq: seq, Partition: p, HostID: "host-1", Source: "sysmon",
		EventTime: t, IngestAt: t.Add(time.Second),
		Fields: map[string]pipe.WireValue{
			"Image":       pipe.WireValue(event.String(`C:\Windows\System32\cmd.exe`)),
			"CommandLine": pipe.WireValue(event.String("cmd /c whoami")),
		},
		Raw: []byte(`{"a":1}`),
	}
}

func normRecord(t *testing.T, n pipe.NormEvent) broker.Record {
	t.Helper()
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	return broker.Record{Topic: pipe.TopicEventsNorm, Partition: broker.AnyPartition, Key: []byte(n.HostID), Value: b}
}

func eventsCommitted(t *testing.T, b broker.Broker) bool {
	t.Helper()
	ctx := context.Background()
	end, err := b.EndOffsets(ctx, pipe.TopicEventsNorm)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.CommittedOffsets(ctx, group, pipe.TopicEventsNorm)
	if err != nil {
		t.Fatal(err)
	}
	for p, off := range end {
		if off > 0 && got[p] != off {
			return false
		}
	}
	return true
}

func runEvents(t *testing.T, s *Lane[ch.Row]) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()
	return func() error {
		cancel()
		return <-errc
	}
}

// The events lane stores each events.norm record as the row ch.Encode
// computes for it, so a retro-hunt reads what v1 would have evaluated.
func TestEventsLaneStoresTheEncodedEventAndCommits(t *testing.T) {
	b := newEventsBroker()
	var want []ch.Row
	var recs []broker.Record
	for i := range 23 {
		n := normEvent(int32(i%3), uint64(i))
		want = append(want, ch.Encode(n.Event()))
		recs = append(recs, normRecord(t, n))
	}
	if err := b.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	tbl := &rowTable{}
	s, err := NewEvents(testConfig(), b, tbl, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runEvents(t, s)
	waitFor(t, "every events.norm offset committed", func() bool { return eventsCommitted(t, b) })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	got := tbl.snapshot()
	key := func(rs []ch.Row) {
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].Partition != rs[j].Partition {
				return rs[i].Partition < rs[j].Partition
			}
			return rs[i].Seq < rs[j].Seq
		})
	}
	key(got)
	key(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stored rows differ from ch.Encode:\ngot  %+v\nwant %+v", got, want)
	}
}

// A record that is not a NormEvent, or whose times the table cannot hold,
// goes to events.dead with its reason, and the lane keeps going.
func TestEventsLaneDeadLettersWhatTheTableCannotHold(t *testing.T) {
	b := newEventsBroker()
	far := normEvent(0, 2)
	far.EventTime = time.Date(2290, 1, 1, 0, 0, 0, 0, time.UTC)
	recs := []broker.Record{
		normRecord(t, normEvent(0, 1)),
		{Topic: pipe.TopicEventsNorm, Partition: 0, Value: []byte("{")},
		normRecord(t, far),
		normRecord(t, normEvent(1, 3)),
	}
	if err := b.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	tbl := &rowTable{}
	s, err := NewEvents(testConfig(), b, tbl, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := runEvents(t, s)
	waitFor(t, "every events.norm offset committed", func() bool { return eventsCommitted(t, b) })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v", err)
	}
	if n := len(tbl.snapshot()); n != 2 {
		t.Fatalf("stored %d rows, want the 2 the table can hold", n)
	}
	dead := readTopic(t, b, pipe.TopicEventsDead)
	if len(dead) != 2 {
		t.Fatalf("%d dead letters, want 2", len(dead))
	}
	for _, d := range dead {
		var topic string
		for _, h := range d.Headers {
			if h.Key == HeaderDeadTopic {
				topic = string(h.Value)
			}
		}
		if topic != pipe.TopicEventsNorm {
			t.Fatalf("dead letter names topic %q, want %s", topic, pipe.TopicEventsNorm)
		}
	}
}

// deploy/clickhouse/003_events.sql creates the table the events lane and the
// retro-hunt share. It must be the DDL ch.CreateTableSQL builds, or the
// positional insert and the compiled WHERE clause read different columns.
func TestEventsDDLIsTheBackendSchema(t *testing.T) {
	b, err := os.ReadFile("../../../deploy/clickhouse/003_events.sql")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ch.CreateTableSQL("signalman.events")
	if err != nil {
		t.Fatal(err)
	}
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	stmts := Statements(string(b))
	if len(stmts) != 1 || norm(stmts[0]) != norm(want) {
		t.Fatalf("003_events.sql is not ch.CreateTableSQL(\"signalman.events\"):\n%s\nwant\n%s", strings.Join(stmts, ";\n"), want)
	}
}
