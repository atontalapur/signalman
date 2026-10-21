package pipe

import (
	"context"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func rawRecord(host, source, body string) broker.Record {
	r := broker.Record{Topic: TopicEventsRaw, Partition: broker.AnyPartition, Key: []byte(host), Value: []byte(body)}
	if source != "" {
		r.Headers = []broker.Header{{Key: HeaderSource, Value: []byte(source)}}
	}
	return r
}

func pollRecords(t *testing.T, c broker.Consumer, n int) []broker.Record {
	t.Helper()
	var out []broker.Record
	for len(out) < n {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		f, err := c.Poll(ctx)
		cancel()
		if err != nil {
			t.Fatalf("poll after %d of %d: %v", len(out), n, err)
		}
		out = append(out, f.Records...)
	}
	return out
}

func TestIngestSeqIsTheOffset(t *testing.T) {
	b := broker.NewMemory(map[string]int32{TopicEventsRaw: 4})
	var recs []broker.Record
	for i := 0; i < 40; i++ {
		recs = append(recs, rawRecord([]string{"h1", "h2", "h3", "h4", "h5"}[i%5], "sysmon", "{}"))
	}
	if err := b.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	c, _ := b.Consume("g", []string{TopicEventsRaw})
	in := NewIngest(obs.New(prometheus.NewRegistry()))

	last := map[int32]uint64{}
	seen := map[int32]bool{}
	for _, r := range pollRecords(t, c, 40) {
		it := in.Admit(r)
		ev := it.Event
		if ev.Seq != uint64(r.Offset) || ev.Partition != r.Partition {
			t.Fatalf("seq %d partition %d for offset %d partition %d", ev.Seq, ev.Partition, r.Offset, r.Partition)
		}
		if seen[ev.Partition] && ev.Seq <= last[ev.Partition] {
			t.Fatalf("partition %d seq went %d -> %d", ev.Partition, last[ev.Partition], ev.Seq)
		}
		seen[ev.Partition], last[ev.Partition] = true, ev.Seq
		if it.HostID != string(r.Key) || ev.Source != "sysmon" || string(ev.Raw) != "{}" {
			t.Fatalf("item %+v from %+v", it, r)
		}
		if !ev.IngestAt.Equal(r.Timestamp) {
			t.Fatal("IngestAt comes from the record timestamp, so a replay reproduces it")
		}
	}
}

func TestIngestSeqSurvivesRestartAndRedelivery(t *testing.T) {
	b := broker.NewMemory(map[string]int32{TopicEventsRaw: 1})
	for i := 0; i < 6; i++ {
		if err := b.Produce(context.Background(), []broker.Record{rawRecord("h", "sysmon", "{}")}); err != nil {
			t.Fatal(err)
		}
	}
	in := NewIngest(obs.New(prometheus.NewRegistry()))

	c, _ := b.Consume("g", []string{TopicEventsRaw})
	first := map[int64]uint64{}
	for _, r := range pollRecords(t, c, 6) {
		first[r.Offset] = in.Admit(r).Event.Seq
	}
	// The process dies after committing through offset 3. Offsets 4 and 5
	// were admitted but not committed, so they come back.
	if err := c.Commit(context.Background(), map[broker.TopicPartition]int64{{Topic: TopicEventsRaw, Partition: 0}: 4}); err != nil {
		t.Fatal(err)
	}
	c.Close()

	c2, _ := b.Consume("g", []string{TopicEventsRaw})
	again := pollRecords(t, c2, 2)
	for _, r := range again {
		seq := in.Admit(r).Event.Seq
		if seq <= first[3] {
			t.Fatalf("seq %d after restart is not past the committed seq %d", seq, first[3])
		}
		if seq != first[r.Offset] {
			t.Fatalf("redelivered offset %d got seq %d, first delivery got %d; the sink dedups on seq", r.Offset, seq, first[r.Offset])
		}
	}
}

func TestIngestCountsPerSourceAndPartition(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := obs.New(reg)
	in := NewIngest(m)
	in.Admit(broker.Record{Topic: TopicEventsRaw, Partition: 2, Offset: 0, Headers: []broker.Header{{Key: HeaderSource, Value: []byte("sysmon")}}})
	in.Admit(broker.Record{Topic: TopicEventsRaw, Partition: 2, Offset: 1, Headers: []broker.Header{{Key: HeaderSource, Value: []byte("sysmon")}}})
	in.Admit(broker.Record{Topic: TopicEventsRaw, Partition: 5, Offset: 0})

	if got := testutil.ToFloat64(m.EventsIngested.WithLabelValues("sysmon", "2")); got != 2 {
		t.Fatalf("sysmon/2 = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.EventsIngested.WithLabelValues(SourceUnknown, "5")); got != 1 {
		t.Fatalf("a record with no source header is still admitted and counted: %v", got)
	}
}
