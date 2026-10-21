//go:build integration

package kafka

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
)

func dial(t *testing.T) *Broker {
	t.Helper()
	addr := os.Getenv("SIGNALMAN_BROKERS")
	if addr == "" {
		addr = "localhost:19092"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := Dial(ctx, Config{Brokers: strings.Split(addr, ","), ClientID: "signalman-it"})
	if err != nil {
		t.Fatalf("redpanda not reachable at %s (docker compose -f deploy/docker-compose.yml up -d --wait): %v", addr, err)
	}
	t.Cleanup(b.Close)
	return b
}

func topic(t *testing.T, b *Broker, partitions int32) string {
	t.Helper()
	name := fmt.Sprintf("it-%s-%d", strings.ToLower(t.Name()), time.Now().UnixNano())
	if err := b.EnsureTopics(context.Background(), []TopicSpec{{Name: name, Partitions: partitions, Replication: 1}}); err != nil {
		t.Fatal(err)
	}
	return name
}

func pollN(t *testing.T, c broker.Consumer, n int) []broker.Record {
	t.Helper()
	var out []broker.Record
	deadline := time.Now().Add(20 * time.Second)
	for len(out) < n {
		if time.Now().After(deadline) {
			t.Fatalf("got %d of %d records", len(out), n)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		f, err := c.Poll(ctx)
		cancel()
		if err != nil && ctx.Err() == nil {
			t.Fatal(err)
		}
		out = append(out, f.Records...)
	}
	return out
}

func TestKafkaProduceConsumeCommitResume(t *testing.T) {
	b := dial(t)
	tp := topic(t, b, 2)
	ctx := context.Background()

	var recs []broker.Record
	for i := 0; i < 10; i++ {
		recs = append(recs, broker.Record{Topic: tp, Partition: broker.AnyPartition, Key: []byte("host-a"), Value: []byte(fmt.Sprint(i))})
	}
	if err := b.Produce(ctx, recs); err != nil {
		t.Fatal(err)
	}
	end, err := b.EndOffsets(ctx, tp)
	if err != nil {
		t.Fatal(err)
	}
	if end[0]+end[1] != 10 || (end[0] != 0 && end[1] != 0) {
		t.Fatalf("one key must land on one partition: %v", end)
	}

	group := tp + "-g"
	c, err := b.Consume(group, []string{tp})
	if err != nil {
		t.Fatal(err)
	}
	got := pollN(t, c, 10)
	for i, r := range got {
		if string(r.Value) != fmt.Sprint(i) || r.Offset != int64(i) {
			t.Fatalf("record %d = %q at offset %d", i, r.Value, r.Offset)
		}
	}
	p := got[0].Partition
	if err := c.Commit(ctx, map[broker.TopicPartition]int64{{Topic: tp, Partition: p}: 6}); err != nil {
		t.Fatal(err)
	}
	c.Close()

	committed, err := b.CommittedOffsets(ctx, group, tp)
	if err != nil {
		t.Fatal(err)
	}
	if committed[p] != 6 {
		t.Fatalf("committed = %v", committed)
	}
	c2, err := b.Consume(group, []string{tp})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	again := pollN(t, c2, 4)
	if again[0].Offset != 6 {
		t.Fatalf("resumed at %d, want 6", again[0].Offset)
	}
}

func TestKafkaPinnedPartitionAndReadFrom(t *testing.T) {
	b := dial(t)
	tp := topic(t, b, 3)
	ctx := context.Background()
	if err := b.Produce(ctx, []broker.Record{
		{Topic: tp, Partition: 2, Value: []byte("x")},
		{Topic: tp, Partition: 2, Value: []byte("y")},
	}); err != nil {
		t.Fatal(err)
	}
	r, err := b.ReadFrom(map[broker.TopicPartition]int64{{Topic: tp, Partition: 2}: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got := pollN(t, r, 1)
	if got[0].Partition != 2 || string(got[0].Value) != "y" {
		t.Fatalf("read %+v", got[0])
	}
	if err := r.Commit(ctx, nil); err == nil {
		t.Fatal("a positioned reader must refuse to commit")
	}
}

func TestKafkaCommitCheckpointsOutsideTheGroup(t *testing.T) {
	b := dial(t)
	name := topic(t, b, 2)
	ctx := context.Background()
	group := "it-commit-" + name
	if err := b.CommitCheckpoints(ctx, group, map[broker.TopicPartition]broker.Checkpoint{{Topic: name, Partition: 1}: {Next: 0, Meta: `{"v":1}`}}); err != nil {
		t.Fatal(err)
	}
	c, err := b.CommittedOffsets(ctx, group, name)
	if err != nil || c[1] != 0 {
		t.Fatalf("committed %v %v", c, err)
	}
	cp, err := b.Checkpoints(ctx, group, name)
	if err != nil || len(cp) != 1 || cp[1] != (broker.Checkpoint{Next: 0, Meta: `{"v":1}`}) {
		t.Fatalf("checkpoints %v %v", cp, err)
	}
}
