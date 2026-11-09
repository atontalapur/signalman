package pipe

import (
	"context"
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/atontalapur/signalman/internal/broker"
)

// owner is a consumer that reports a fixed set of owned partitions, as a
// group member does after a rebalance.
type owner struct {
	broker.Consumer
	parts []broker.TopicPartition
}

func (o owner) Owned() []broker.TopicPartition { return o.parts }

func lagRig(t *testing.T) (*broker.Memory, *prometheus.GaugeVec, *Lag) {
	t.Helper()
	mem := newMemory()
	var recs []broker.Record
	for i := range 40 {
		r := genRaw(i)
		r.Partition = int32(i % testPartitions)
		recs = append(recs, r)
	}
	if err := mem.Produce(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "lag"}, []string{"topic", "partition"})
	return mem, g, NewLag(mem, "signalmand", TopicEventsRaw, g)
}

func tp(p int32) broker.TopicPartition {
	return broker.TopicPartition{Topic: TopicEventsRaw, Partition: p}
}

func gauge(g *prometheus.GaugeVec, p int) float64 {
	return testutil.ToFloat64(g.WithLabelValues(TopicEventsRaw, strconv.Itoa(p)))
}

// A partition a rebalance took away stops being reported, and its series
// goes, so the group's members do not count it twice.
func TestLagReportsOnlyOwnedPartitions(t *testing.T) {
	mem, g, l := lagRig(t)
	ends, err := mem.EndOffsets(context.Background(), TopicEventsRaw)
	if err != nil {
		t.Fatal(err)
	}
	l.Observe(map[broker.TopicPartition]int64{tp(0): ends[0], tp(1): ends[1]})
	if n := testutil.CollectAndCount(g); n != 2 {
		t.Fatalf("%d series after observing two partitions", n)
	}
	l.Refresh(context.Background(), owner{parts: []broker.TopicPartition{tp(0), tp(2)}})
	if n := testutil.CollectAndCount(g); n != 2 {
		t.Fatalf("%d series after the rebalance; want partitions 0 and 2", n)
	}
	if v := gauge(g, 2); v != float64(ends[2]) {
		t.Fatalf("newly owned partition 2 lag %v, want %d", v, ends[2])
	}
	if v := gauge(g, 0); v != float64(ends[0]) {
		t.Fatalf("partition 0 lag %v, want %d", v, ends[0])
	}
}

// A partition gained in a rebalance is measured against what the group
// committed, not against this process's snapshot from before another
// member moved it on.
func TestLagUsesTheGroupsCommittedOffsets(t *testing.T) {
	mem, g, l := lagRig(t)
	if err := l.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	other, err := mem.Consume("signalmand", []string{TopicEventsRaw})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.Commit(context.Background(), map[broker.TopicPartition]int64{tp(3): 7}); err != nil {
		t.Fatal(err)
	}
	ends, _ := mem.EndOffsets(context.Background(), TopicEventsRaw)
	l.Refresh(context.Background(), owner{parts: []broker.TopicPartition{tp(3)}})
	if v := gauge(g, 3); v != float64(ends[3]-7) {
		t.Fatalf("partition 3 lag %v, want %d (log end %d minus the group's commit 7)", v, ends[3]-7, ends[3])
	}
}

// A poll result older than a refresh does not move the log end back.
func TestLagLogEndNeverMovesBack(t *testing.T) {
	mem, g, l := lagRig(t)
	ends, _ := mem.EndOffsets(context.Background(), TopicEventsRaw)
	l.Refresh(context.Background(), owner{parts: []broker.TopicPartition{tp(0)}})
	l.Observe(map[broker.TopicPartition]int64{tp(0): ends[0] - 5})
	if v := gauge(g, 0); v != float64(ends[0]) {
		t.Fatalf("lag %v after a stale poll; want %d", v, ends[0])
	}
}

// The group's committed offset wins over this process's record, which can
// name a commit the broker dropped for a partition this member had lost.
func TestLagGroupCommitOverridesLocal(t *testing.T) {
	mem, g, l := lagRig(t)
	other, err := mem.Consume("signalmand", []string{TopicEventsRaw})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.Commit(context.Background(), map[broker.TopicPartition]int64{tp(1): 3}); err != nil {
		t.Fatal(err)
	}
	l.Committed(map[broker.TopicPartition]int64{tp(1): 9}) // dropped by the broker
	ends, _ := mem.EndOffsets(context.Background(), TopicEventsRaw)
	l.Refresh(context.Background(), owner{parts: []broker.TopicPartition{tp(1)}})
	if v := gauge(g, 1); v != float64(ends[1]-3) {
		t.Fatalf("partition 1 lag %v, want %d against the group's commit 3", v, ends[1]-3)
	}
}

// A partition the group never committed counts from the log start, not
// from offset 0: retention already removed what is below it.
func TestLagUncommittedPartitionCountsFromLogStart(t *testing.T) {
	mem, g, l := lagRig(t)
	mem.Trim(tp(2), 6)
	ends, _ := mem.EndOffsets(context.Background(), TopicEventsRaw)
	l.Refresh(context.Background(), owner{parts: []broker.TopicPartition{tp(2)}})
	if v := gauge(g, 2); v != float64(ends[2]-6) {
		t.Fatalf("partition 2 lag %v, want %d from the log start 6", v, ends[2]-6)
	}
}

// A poll result from before a revoke does not bring back the series the
// refresh deleted.
func TestLagStalePollAfterRevokeStaysDeleted(t *testing.T) {
	mem, g, l := lagRig(t)
	ends, _ := mem.EndOffsets(context.Background(), TopicEventsRaw)
	l.Observe(map[broker.TopicPartition]int64{tp(0): ends[0], tp(1): ends[1]})
	l.Refresh(context.Background(), owner{parts: []broker.TopicPartition{tp(0)}})
	l.Observe(map[broker.TopicPartition]int64{tp(1): ends[1]})
	if n := testutil.CollectAndCount(g); n != 1 {
		t.Fatalf("%d series after a stale poll for revoked partition 1; want 1", n)
	}
}
