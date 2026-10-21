package broker

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"sync"
	"time"
)

// Memory is an in-process broker for tests. It keeps every record ever
// produced, so it is for bounded test runs, not for soaks.
//
// It keeps the contracts in broker.go: dense per-partition offsets, slice
// order within a partition, records durable on return from Produce, and
// group offsets that change only on Commit. A group has one member, which
// owns every partition; there is no rebalancing.
type Memory struct {
	mu      sync.Mutex
	topics  map[string][][]Record
	groups  map[string]map[TopicPartition]int64
	notify  chan struct{}
	maxPoll int
	now     func() time.Time
}

// MemoryOption configures a Memory broker.
type MemoryOption func(*Memory)

// WithMaxPoll caps how many records one Poll returns. The default is 500.
func WithMaxPoll(n int) MemoryOption { return func(m *Memory) { m.maxPoll = n } }

// WithClock sets the source of record timestamps.
func WithClock(now func() time.Time) MemoryOption { return func(m *Memory) { m.now = now } }

// NewMemory creates the given topics with the given partition counts.
func NewMemory(topics map[string]int32, opts ...MemoryOption) *Memory {
	m := &Memory{
		topics:  make(map[string][][]Record, len(topics)),
		groups:  map[string]map[TopicPartition]int64{},
		notify:  make(chan struct{}),
		maxPoll: 500,
		now:     time.Now,
	}
	for t, n := range topics {
		m.topics[t] = make([][]Record, n)
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

func keyPartition(key []byte, n int) int32 {
	if len(key) == 0 {
		return 0
	}
	h := fnv.New32a()
	h.Write(key)
	return int32(h.Sum32() % uint32(n))
}

// Produce appends recs. It validates the whole slice before writing any of
// it, so a bad record fails the call without a partial write.
func (m *Memory) Produce(ctx context.Context, recs []Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	parts := make([]int32, len(recs))
	for i, r := range recs {
		ps, ok := m.topics[r.Topic]
		if !ok {
			return fmt.Errorf("produce: unknown topic %q", r.Topic)
		}
		p := r.Partition
		if p == AnyPartition {
			p = keyPartition(r.Key, len(ps))
		}
		if p < 0 || int(p) >= len(ps) {
			return fmt.Errorf("produce: topic %q has no partition %d", r.Topic, r.Partition)
		}
		parts[i] = p
	}
	ts := m.now()
	for i, r := range recs {
		p := parts[i]
		log := m.topics[r.Topic][p]
		r.Partition = p
		r.Offset = int64(len(log))
		if r.Timestamp.IsZero() {
			r.Timestamp = ts
		}
		m.topics[r.Topic][p] = append(log, r)
	}
	if len(recs) > 0 {
		close(m.notify)
		m.notify = make(chan struct{})
	}
	return nil
}

// Consume returns a consumer for group over every partition of topics.
func (m *Memory) Consume(group string, topics []string) (Consumer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := &memConsumer{m: m, group: group, pos: map[TopicPartition]int64{}}
	committed := m.groups[group]
	for _, t := range topics {
		ps, ok := m.topics[t]
		if !ok {
			return nil, fmt.Errorf("consume: unknown topic %q", t)
		}
		for p := range ps {
			tp := TopicPartition{t, int32(p)}
			c.order = append(c.order, tp)
			c.pos[tp] = committed[tp]
		}
	}
	return c, nil
}

// ReadFrom returns a groupless reader positioned at start.
func (m *Memory) ReadFrom(start map[TopicPartition]int64) (Consumer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := &memConsumer{m: m, pos: map[TopicPartition]int64{}}
	for tp, off := range start {
		ps, ok := m.topics[tp.Topic]
		if !ok || tp.Partition < 0 || int(tp.Partition) >= len(ps) {
			return nil, fmt.Errorf("read: no partition %s/%d", tp.Topic, tp.Partition)
		}
		c.order = append(c.order, tp)
		c.pos[tp] = off
	}
	sort.Slice(c.order, func(i, j int) bool {
		if c.order[i].Topic != c.order[j].Topic {
			return c.order[i].Topic < c.order[j].Topic
		}
		return c.order[i].Partition < c.order[j].Partition
	})
	return c, nil
}

func (m *Memory) EndOffsets(ctx context.Context, topic string) (map[int32]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ps, ok := m.topics[topic]
	if !ok {
		return nil, fmt.Errorf("end offsets: unknown topic %q", topic)
	}
	out := make(map[int32]int64, len(ps))
	for p, log := range ps {
		out[int32(p)] = int64(len(log))
	}
	return out, nil
}

func (m *Memory) CommittedOffsets(ctx context.Context, group, topic string) (map[int32]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.topics[topic]; !ok {
		return nil, fmt.Errorf("committed offsets: unknown topic %q", topic)
	}
	out := map[int32]int64{}
	for tp, off := range m.groups[group] {
		if tp.Topic == topic {
			out[tp.Partition] = off
		}
	}
	return out, nil
}

func (m *Memory) Close() {}

type memConsumer struct {
	m      *Memory
	group  string // empty for a positioned reader
	order  []TopicPartition
	pos    map[TopicPartition]int64
	cursor int // rotates the starting partition so none is starved
	closed bool
}

var errClosed = errors.New("consumer closed")

func (c *memConsumer) Poll(ctx context.Context) (Fetch, error) {
	for {
		c.m.mu.Lock()
		if c.closed {
			c.m.mu.Unlock()
			return Fetch{}, errClosed
		}
		f := c.take()
		wait := c.m.notify
		c.m.mu.Unlock()
		if len(f.Records) > 0 {
			return f, nil
		}
		select {
		case <-ctx.Done():
			return Fetch{}, ctx.Err()
		case <-wait:
		}
	}
}

// take collects up to maxPoll records, starting from a rotating partition.
// Caller holds the lock.
func (c *memConsumer) take() Fetch {
	f := Fetch{HighWatermarks: map[TopicPartition]int64{}}
	n := len(c.order)
	for i := 0; i < n && len(f.Records) < c.m.maxPoll; i++ {
		tp := c.order[(c.cursor+i)%n]
		log := c.m.topics[tp.Topic][tp.Partition]
		f.HighWatermarks[tp] = int64(len(log))
		for c.pos[tp] < int64(len(log)) && len(f.Records) < c.m.maxPoll {
			f.Records = append(f.Records, log[c.pos[tp]])
			c.pos[tp]++
		}
	}
	if n > 0 {
		c.cursor = (c.cursor + 1) % n
	}
	return f
}

func (c *memConsumer) Commit(ctx context.Context, next map[TopicPartition]int64) error {
	if c.group == "" {
		return errors.New("commit: a positioned reader has no group")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.m.mu.Lock()
	defer c.m.mu.Unlock()
	g := c.m.groups[c.group]
	if g == nil {
		g = map[TopicPartition]int64{}
		c.m.groups[c.group] = g
	}
	for tp, off := range next {
		g[tp] = off
	}
	return nil
}

func (c *memConsumer) Close() {
	c.m.mu.Lock()
	c.closed = true
	c.m.mu.Unlock()
}
