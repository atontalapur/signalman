package pipe

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/atontalapur/signalman/internal/broker"
)

// Lag keeps signalman_consumer_lag_records for one consumer group on one
// topic: per partition, the log end minus the group's committed offset.
//
// Polls report log ends, but a consumer stops polling exactly when its
// backlog grows: a stalled stage blocks ingest on a full queue, and a sink
// retrying an insert does not poll. So Run also refreshes the gauge from
// the broker on a ticker of its own. A refresh reads the group's committed
// offsets too, because after a rebalance this process's own record of them
// is a snapshot from before another member committed.
//
// Only partitions this consumer owns are reported. A consumer that
// implements broker.Owner says which; one that does not is taken to own
// what its polls have reported. The series of a partition no longer owned
// is deleted, so summing over the group's members does not count it twice.
type Lag struct {
	b     broker.Broker
	group string
	topic string
	gauge *prometheus.GaugeVec // nil disables the gauge

	mu        sync.Mutex
	hw        map[broker.TopicPartition]int64
	committed map[broker.TopicPartition]int64
}

// lagRefreshTimeout bounds each broker lookup a refresh makes.
const lagRefreshTimeout = 2 * time.Second

// NewLag tracks lag for group on topic. gauge may be nil.
func NewLag(b broker.Broker, group, topic string, gauge *prometheus.GaugeVec) *Lag {
	return &Lag{
		b: b, group: group, topic: topic, gauge: gauge,
		hw:        map[broker.TopicPartition]int64{},
		committed: map[broker.TopicPartition]int64{},
	}
}

// Load reads the group's committed offsets, before the first poll.
func (l *Lag) Load(ctx context.Context) error {
	c, err := l.b.CommittedOffsets(ctx, l.group, l.topic)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for p, off := range c {
		tp := broker.TopicPartition{Topic: l.topic, Partition: p}
		l.committed[tp] = max(l.committed[tp], off)
	}
	return nil
}

// Observe records the log ends a poll reported.
func (l *Lag) Observe(hw map[broker.TopicPartition]int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for tp, off := range hw {
		// A log end never moves back. A refresh may have stored a newer
		// one than this poll saw.
		l.hw[tp] = max(l.hw[tp], off)
		l.set(tp)
	}
}

// Committed records offsets this process committed.
func (l *Lag) Committed(next map[broker.TopicPartition]int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for tp, off := range next {
		l.committed[tp] = max(l.committed[tp], off)
		l.set(tp)
	}
}

// Run refreshes the gauge every interval until ctx ends.
func (l *Lag) Run(ctx context.Context, cons broker.Consumer, interval time.Duration) {
	if l.gauge == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Refresh(ctx, cons)
		}
	}
}

// Refresh recomputes the gauge from the broker's log ends and the group's
// committed offsets. A failed lookup leaves the gauge as it was; the broker
// may be what is down.
func (l *Lag) Refresh(ctx context.Context, cons broker.Consumer) {
	ctx, cancel := context.WithTimeout(ctx, lagRefreshTimeout)
	defer cancel()
	ends, err := l.b.EndOffsets(ctx, l.topic)
	if err != nil {
		return
	}
	group, err := l.b.CommittedOffsets(ctx, l.group, l.topic)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	owned := l.owned(cons)
	for tp := range l.hw {
		if !owned[tp] {
			delete(l.hw, tp)
			if l.gauge != nil {
				l.gauge.DeleteLabelValues(tp.Topic, strconv.Itoa(int(tp.Partition)))
			}
		}
	}
	for tp := range owned {
		if tp.Topic != l.topic {
			continue
		}
		if end, ok := ends[tp.Partition]; ok {
			l.hw[tp] = max(l.hw[tp], end)
		}
		if c, ok := group[tp.Partition]; ok {
			l.committed[tp] = max(l.committed[tp], c)
		}
		l.set(tp)
	}
}

// owned is the set of partitions to report. Caller holds l.mu.
func (l *Lag) owned(cons broker.Consumer) map[broker.TopicPartition]bool {
	set := map[broker.TopicPartition]bool{}
	if o, ok := cons.(broker.Owner); ok {
		for _, tp := range o.Owned() {
			set[tp] = true
		}
		return set
	}
	for tp := range l.hw {
		set[tp] = true
	}
	return set
}

// set writes one partition's gauge. Caller holds l.mu.
func (l *Lag) set(tp broker.TopicPartition) {
	hw, ok := l.hw[tp]
	if !ok || l.gauge == nil {
		return
	}
	l.gauge.WithLabelValues(tp.Topic, strconv.Itoa(int(tp.Partition))).Set(float64(max(0, hw-l.committed[tp])))
}
