package kafka

import (
	"maps"
	"slices"
	"sync"

	"github.com/atontalapur/signalman/internal/broker"
)

// ownership decides which offsets a group consumer may still commit.
//
// The pipeline commits a batch after its outputs are durable, which can be
// after a rebalance took the batch's partition away. That stale commit
// would overwrite the new owner's progress and move the group offset back.
// So a partition is committable only while this member owns it, only once
// a record has been polled for it since it was assigned, and only forward
// of where that assignment started or last committed.
//
// Commit holds mu across the broker round trip, and the rebalance callbacks
// take mu, so a revoke waits for a commit in flight (made while this member
// was still the owner) and every commit after the revoke sees it. franz-go
// runs the callbacks outside its join and sync, where commits block, so
// this cannot deadlock.
type ownership struct {
	mu sync.Mutex
	// floor is, per owned partition, the lowest next offset a commit may
	// name; -1 until the first record since assignment is polled.
	floor map[broker.TopicPartition]int64
}

func each(m map[string][]int32, fn func(broker.TopicPartition)) {
	for t, ps := range m {
		for _, p := range ps {
			fn(broker.TopicPartition{Topic: t, Partition: p})
		}
	}
}

func (o *ownership) assign(m map[string][]int32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.floor == nil {
		o.floor = map[broker.TopicPartition]int64{}
	}
	each(m, func(tp broker.TopicPartition) { o.floor[tp] = -1 })
}

// owned lists the partitions currently assigned.
func (o *ownership) owned() []broker.TopicPartition {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Collect(maps.Keys(o.floor))
}

func (o *ownership) revoke(m map[string][]int32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	each(m, func(tp broker.TopicPartition) { delete(o.floor, tp) })
}

func (o *ownership) lose() {
	o.mu.Lock()
	defer o.mu.Unlock()
	clear(o.floor)
}

// polled records that off was returned for tp.
func (o *ownership) polled(tp broker.TopicPartition, off int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if f, ok := o.floor[tp]; ok && f < 0 {
		o.floor[tp] = off
	}
}

func (o *ownership) filter(next map[broker.TopicPartition]int64) map[broker.TopicPartition]int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.filterLocked(next)
}

func (o *ownership) committed(next map[broker.TopicPartition]int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.committedLocked(next)
}

func (o *ownership) filterLocked(next map[broker.TopicPartition]int64) map[broker.TopicPartition]int64 {
	keep := make(map[broker.TopicPartition]int64, len(next))
	for tp, off := range next {
		if f, ok := o.floor[tp]; ok && f >= 0 && off > f {
			keep[tp] = off
		}
	}
	return keep
}

func (o *ownership) committedLocked(next map[broker.TopicPartition]int64) {
	for tp, off := range next {
		if f, ok := o.floor[tp]; ok && off > f {
			o.floor[tp] = off
		}
	}
}
