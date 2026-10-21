package kafka

import (
	"maps"
	"testing"

	"github.com/atontalapur/signalman/internal/broker"
)

func TestOwnershipDropsCommitsForPartitionsThisMemberLost(t *testing.T) {
	p0 := broker.TopicPartition{Topic: "events.raw", Partition: 0}
	p1 := broker.TopicPartition{Topic: "events.raw", Partition: 1}
	var o ownership
	o.assign(map[string][]int32{"events.raw": {0, 1}})
	o.polled(p0, 10)
	o.polled(p1, 20)

	// A batch polled before the revoke finishes after it.
	o.revoke(map[string][]int32{"events.raw": {1}})
	got := o.filter(map[broker.TopicPartition]int64{p0: 15, p1: 30})
	if !maps.Equal(got, map[broker.TopicPartition]int64{p0: 15}) {
		t.Fatalf("filter = %v; a revoked partition's stale commit is dropped", got)
	}
	o.committed(got)

	// Reassigned: until a record is polled, nothing for it is committable,
	// and afterwards nothing below where the new assignment started.
	o.assign(map[string][]int32{"events.raw": {1}})
	if got := o.filter(map[broker.TopicPartition]int64{p1: 30}); len(got) != 0 {
		t.Fatalf("filter = %v before the reassigned partition was polled", got)
	}
	o.polled(p1, 50) // the other member had committed 50
	if got := o.filter(map[broker.TopicPartition]int64{p1: 30}); len(got) != 0 {
		t.Fatalf("filter = %v; a stale commit would move the group offset back from 50", got)
	}
	if got := o.filter(map[broker.TopicPartition]int64{p1: 60}); got[p1] != 60 {
		t.Fatalf("filter = %v; a commit from the new assignment goes through", got)
	}

	// Commits never move backwards within an assignment either.
	if got := o.filter(map[broker.TopicPartition]int64{p0: 12}); len(got) != 0 {
		t.Fatalf("filter = %v; 15 was already committed for partition 0", got)
	}
	o.lose()
	if got := o.filter(map[broker.TopicPartition]int64{p0: 99}); len(got) != 0 {
		t.Fatalf("filter = %v after every partition was lost", got)
	}
}
