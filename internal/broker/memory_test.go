package broker

import (
	"context"
	"errors"
	"testing"
	"time"
)

func produce(t *testing.T, b Broker, recs ...Record) {
	t.Helper()
	if err := b.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
}

func pollAll(t *testing.T, c Consumer, want int) []Record {
	t.Helper()
	var out []Record
	for len(out) < want {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		f, err := c.Poll(ctx)
		cancel()
		if err != nil {
			t.Fatalf("poll after %d of %d records: %v", len(out), want, err)
		}
		out = append(out, f.Records...)
	}
	return out
}

func TestMemoryAssignsDenseOffsetsPerPartition(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 2})
	produce(t, m,
		Record{Topic: "t", Partition: 0, Value: []byte("a")},
		Record{Topic: "t", Partition: 1, Value: []byte("b")},
		Record{Topic: "t", Partition: 0, Value: []byte("c")},
	)
	end, err := m.EndOffsets(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	if end[0] != 2 || end[1] != 1 {
		t.Fatalf("end offsets = %v, want {0:2 1:1}", end)
	}
	c, _ := m.ReadFrom(map[TopicPartition]int64{{"t", 0}: 0})
	got := pollAll(t, c, 2)
	if got[0].Offset != 0 || got[1].Offset != 1 || string(got[1].Value) != "c" {
		t.Fatalf("partition 0 = %+v", got)
	}
}

func TestMemoryKeyPartitioningIsStable(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 8})
	for i := 0; i < 20; i++ {
		produce(t, m, Record{Topic: "t", Partition: AnyPartition, Key: []byte("host-7")})
	}
	end, _ := m.EndOffsets(context.Background(), "t")
	nonEmpty := 0
	for _, n := range end {
		if n > 0 {
			nonEmpty++
			if n != 20 {
				t.Fatalf("one key landed on more than one partition: %v", end)
			}
		}
	}
	if nonEmpty != 1 {
		t.Fatalf("one key must map to exactly one partition: %v", end)
	}
}

func TestMemoryGroupResumesFromCommit(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 1})
	for i := 0; i < 5; i++ {
		produce(t, m, Record{Topic: "t", Partition: 0})
	}
	c, err := m.Consume("g", []string{"t"})
	if err != nil {
		t.Fatal(err)
	}
	got := pollAll(t, c, 5)
	// Commit only the first three: the other two were read but not
	// committed, so a restart must see them again.
	if err := c.Commit(context.Background(), map[TopicPartition]int64{{"t", 0}: got[2].Offset + 1}); err != nil {
		t.Fatal(err)
	}
	c.Close()

	c2, _ := m.Consume("g", []string{"t"})
	again := pollAll(t, c2, 2)
	if again[0].Offset != 3 || again[1].Offset != 4 {
		t.Fatalf("restart read %+v, want offsets 3 and 4", again)
	}
	committed, _ := m.CommittedOffsets(context.Background(), "g", "t")
	if committed[0] != 3 {
		t.Fatalf("committed = %v", committed)
	}
}

func TestMemoryPollBlocksUntilData(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 1})
	c, _ := m.Consume("g", []string{"t"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Poll(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("empty poll = %v, want deadline", err)
	}
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = m.Produce(context.Background(), []Record{{Topic: "t", Partition: 0}})
	}()
	if got := pollAll(t, c, 1); len(got) != 1 {
		t.Fatal(got)
	}
}

func TestMemoryReportsHighWatermarks(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 1}, WithMaxPoll(2))
	for i := 0; i < 5; i++ {
		produce(t, m, Record{Topic: "t", Partition: 0})
	}
	c, _ := m.Consume("g", []string{"t"})
	f, err := c.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Records) != 2 {
		t.Fatalf("max poll ignored: %d records", len(f.Records))
	}
	if hw := f.HighWatermarks[TopicPartition{"t", 0}]; hw != 5 {
		t.Fatalf("high watermark = %d, want 5", hw)
	}
}

func TestMemoryRejectsUnknownTopicAndBadPartition(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 1})
	if err := m.Produce(context.Background(), []Record{{Topic: "nope"}}); err == nil {
		t.Fatal("produce to an unknown topic must fail")
	}
	if err := m.Produce(context.Background(), []Record{{Topic: "t", Partition: 4}}); err == nil {
		t.Fatal("produce to a partition that does not exist must fail")
	}
	r, _ := m.ReadFrom(map[TopicPartition]int64{{"t", 0}: 0})
	if err := r.Commit(context.Background(), nil); err == nil {
		t.Fatal("a positioned reader has no group to commit to")
	}
}

func TestMemoryProduceErrorsThatCannotSucceedArePermanent(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 1}, WithMaxRecordBytes(100))
	for name, rec := range map[string]Record{
		"unknown topic":     {Topic: "nope"},
		"missing partition": {Topic: "t", Partition: 4},
		"too large":         {Topic: "t", Partition: AnyPartition, Key: []byte("k"), Value: make([]byte, 100)},
	} {
		err := m.Produce(context.Background(), []Record{rec})
		if !errors.Is(err, ErrPermanent) {
			t.Fatalf("%s: err = %v, want one wrapping ErrPermanent", name, err)
		}
	}
	end, _ := m.EndOffsets(context.Background(), "t")
	if end[0] != 0 {
		t.Fatal("a rejected produce writes nothing")
	}
	produce(t, m, Record{Topic: "t", Partition: AnyPartition, Key: []byte("k"), Value: make([]byte, 99)})
}

func TestMemoryDefaultRecordLimitIsMaxMessageBytes(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 1})
	err := m.Produce(context.Background(), []Record{{Topic: "t", Partition: AnyPartition, Value: make([]byte, MaxMessageBytes+1)}})
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("err = %v; a record over MaxMessageBytes is refused like a broker would", err)
	}
}

func TestMemoryTrimMovesTheLogStart(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 2})
	for range 5 {
		produce(t, m, Record{Topic: "t", Partition: 1, Value: []byte("x")})
	}
	m.Trim(TopicPartition{"t", 1}, 3)
	start, err := m.StartOffsets(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	if start[0] != 0 || start[1] != 3 {
		t.Fatalf("start offsets = %v, want 0 and 3", start)
	}
	c, err := m.Consume("g", []string{"t"})
	if err != nil {
		t.Fatal(err)
	}
	got := pollAll(t, c, 2)
	if got[0].Offset != 3 || got[1].Offset != 4 {
		t.Fatalf("a group with no commit resumes at the log start: %+v", got)
	}
	r, _ := m.ReadFrom(map[TopicPartition]int64{{"t", 1}: 0})
	if got := pollAll(t, r, 2); got[0].Offset != 3 {
		t.Fatalf("a read below the log start begins at it, got offset %d", got[0].Offset)
	}
}
