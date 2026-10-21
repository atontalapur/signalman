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

func TestMemoryCommitOffsetsWithoutJoiningTheGroup(t *testing.T) {
	m := NewMemory(map[string]int32{"t": 2})
	ctx := context.Background()
	if err := m.CommitOffsets(ctx, "differ", map[TopicPartition]int64{{"t", 1}: 7}); err != nil {
		t.Fatal(err)
	}
	c, err := m.CommittedOffsets(ctx, "differ", "t")
	if err != nil || c[1] != 7 || len(c) != 1 {
		t.Fatalf("committed %v %v", c, err)
	}
	if err := m.CommitOffsets(ctx, "differ", map[TopicPartition]int64{{"t", 2}: 1}); err == nil {
		t.Fatal("a commit to a partition that does not exist is an error")
	}
}
