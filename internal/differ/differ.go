package differ

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/engine/v2"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/prometheus/client_golang/prometheus"
)

// Config sizes the differ.
type Config struct {
	// Group is the name its committed offsets are stored under, on both
	// verdict topics. Default "differ".
	Group string
	// Queue is the capacity of each side's channel per partition: how many
	// records one side may run ahead of the other before its reader stops.
	// Default 256.
	Queue int
	// CommitInterval is how often offsets are committed. Default 1s.
	CommitInterval time.Duration
	// RetryBackoff is the first wait after a failed produce or poll. Waits
	// double up to 5s. Default 100ms.
	RetryBackoff time.Duration
}

// Metrics is what the differ exports. The cutover gates read Counted:
// G1 requires it to stay at zero for seven days.
type Metrics struct {
	// Events counts events resolved: both records compared, or one
	// record whose partner can no longer arrive.
	Events prometheus.Counter
	// Divergences counts divergences by class, version skew included.
	Divergences *prometheus.CounterVec
	// Counted counts divergences in the three zero-budget classes.
	Counted prometheus.Counter
	// Read counts verdict records handed to the join, by engine.
	Read *prometheus.CounterVec
}

// NewMetrics registers the differ's metrics on reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Events: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "signalman_differ_events_total",
			Help: "Events the differ resolved: both verdict records compared, or one found without its partner.",
		}),
		Divergences: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_divergences_total",
			Help: "Disagreements between v1 and v2 per (partition, seq, rule_id), by class.",
		}, []string{"class"}),
		Counted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "signalman_divergences_counted_total",
			Help: "Divergences in the zero-budget classes: v2 false negative, v2 false positive, missing verdict.",
		}),
		Read: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_differ_records_read_total",
			Help: "Verdict records the differ read, by engine.",
		}, []string{"engine"}),
	}
	for _, c := range Classes {
		m.Divergences.WithLabelValues(string(c))
	}
	reg.MustRegister(m.Events, m.Divergences, m.Counted, m.Read)
	return m
}

// Differ joins verdicts.v1 and verdicts.v2 partition by partition.
//
// Each partition has one reader per topic feeding a bounded channel and
// one joiner merging the two. Within a partition both topics are written in
// Seq order, and a redelivered batch rewrites seqs already seen, so after
// dropping repeats each side is a strictly increasing run of seqs. The join
// is then a merge of two sorted sequences: when the heads have the same
// seq they are compared; when one head is behind, the other side has moved
// past it and will never write it, so it is reported missing. A side with
// nothing to read is waited for, never assumed missing: lag over loss. The
// merge holds one head per side, and the channels and one poll per reader
// are the whole buffer, so memory is bounded by Queue and the poll size,
// not by how far one side falls behind.
//
// A v1 record names the shadow it was evaluated alongside. A v1 record
// with no shadow owes no v2 record and is passed over without waiting.
//
// Divergence records are produced before the offsets that cover them are
// committed, so a restart repeats work rather than skipping it: a
// divergence written twice carries the same (partition, seq, rule_id). The
// repeat-dropping state is committed with each offset as its metadata, so
// a restart drops exactly the repeats the stopped differ would have.
type Differ struct {
	cfg Config
	b   broker.Broker
	m   *Metrics
	log *slog.Logger
}

// New builds a differ. log may be nil.
func New(cfg Config, b broker.Broker, m *Metrics, log *slog.Logger) (*Differ, error) {
	if cfg.Group == "" {
		cfg.Group = "differ"
	}
	if cfg.Queue < 0 {
		return nil, fmt.Errorf("differ: queue %d", cfg.Queue)
	}
	if cfg.Queue == 0 {
		cfg.Queue = 256
	}
	if cfg.CommitInterval <= 0 {
		cfg.CommitInterval = time.Second
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 100 * time.Millisecond
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Differ{cfg: cfg, b: b, m: m, log: log}, nil
}

type record struct {
	ev  pipe.EventVerdicts
	off int64
}

// Run joins until ctx ends or a record cannot be read. An unreadable
// verdict record stops the differ: it is a broken data contract, and
// skipping it would hide whatever it held.
func (d *Differ) Run(ctx context.Context) error {
	n, err := d.partitions(ctx)
	if err != nil {
		return err
	}
	start := map[string]map[int32]broker.Checkpoint{}
	for _, t := range []string{pipe.TopicVerdictsV1, pipe.TopicVerdictsV2} {
		if start[t], err = d.b.Checkpoints(ctx, d.cfg.Group, t); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg    sync.WaitGroup
		once  sync.Once
		first error
	)
	fail := func(err error) {
		if err != nil && !errors.Is(err, context.Canceled) {
			once.Do(func() { first = err; cancel() })
		}
	}
	for p := range n {
		a := make(chan record, d.cfg.Queue)
		b := make(chan record, d.cfg.Queue)
		j := &joiner{d: d, part: p,
			sides: [2]*sideState{
				{ch: a, tp: broker.TopicPartition{Topic: pipe.TopicVerdictsV1, Partition: p}},
				{ch: b, tp: broker.TopicPartition{Topic: pipe.TopicVerdictsV2, Partition: p}},
			}}
		for i, s := range j.sides {
			s.restore(start[s.tp.Topic][p], d.log)
			tp, from := s.tp, s.next
			eng := []string{v1.Name, v2.Name}[i]
			out := []chan record{a, b}[i]
			wg.Go(func() { fail(d.read(ctx, tp, from, eng, out)) })
		}
		wg.Go(func() { fail(j.run(ctx)) })
	}
	wg.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}

// partitions returns the partition count shared by both verdict topics and
// the divergence topic. The join is on partition, so they must agree.
func (d *Differ) partitions(ctx context.Context) (int32, error) {
	var n int32 = -1
	for _, t := range []string{pipe.TopicVerdictsV1, pipe.TopicVerdictsV2, TopicDivergences} {
		end, err := d.b.EndOffsets(ctx, t)
		if err != nil {
			return 0, err
		}
		if n >= 0 && int32(len(end)) != n {
			return 0, fmt.Errorf("differ: %s has %d partitions, %s has %d; the join is per partition",
				t, len(end), pipe.TopicVerdictsV1, n)
		}
		n = int32(len(end))
	}
	return n, nil
}

// read feeds one partition of one verdict topic into out, in offset order.
// A full channel blocks it, which stops it polling.
func (d *Differ) read(ctx context.Context, tp broker.TopicPartition, from int64, engine string, out chan<- record) error {
	c, err := d.b.ReadFrom(map[broker.TopicPartition]int64{tp: from})
	if err != nil {
		return err
	}
	defer c.Close()
	wait := d.cfg.RetryBackoff
	for {
		f, err := c.Poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			d.log.Warn("differ: poll failed, retrying", "topic", tp.Topic, "partition", tp.Partition, "err", err)
			if !sleep(ctx, wait) {
				return ctx.Err()
			}
			wait = min(2*wait, 5*time.Second)
			continue
		}
		wait = d.cfg.RetryBackoff
		for _, r := range f.Records {
			var ev pipe.EventVerdicts
			if err := json.Unmarshal(r.Value, &ev); err != nil {
				return fmt.Errorf("differ: unreadable record %s/%d@%d: %w", r.Topic, r.Partition, r.Offset, err)
			}
			if ev.Engine != engine || ev.Partition != tp.Partition {
				return fmt.Errorf("differ: record %s/%d@%d is engine %q partition %d", r.Topic, r.Partition, r.Offset, ev.Engine, ev.Partition)
			}
			select {
			case out <- record{ev: ev, off: r.Offset}:
				d.m.Read.WithLabelValues(engine).Inc()
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// sideState is one verdict topic's partition as the joiner sees it.
type sideState struct {
	ch   <-chan record
	tp   broker.TopicPartition
	head *record
	// peek is v1's record after head, read while head waits on v2, and
	// skip the offset after the repeats read ahead of it, which next moves
	// to once head is handled.
	peek *record
	skip int64
	cur  cursor // what the records below next leave behind
	next int64  // offset after the last record fully handled
	// committed is the checkpoint last committed.
	committed broker.Checkpoint
}

// cursor is the repeat-dropping state of one side: the highest seq handled
// and, on v1, the highest seq handled with a shadow beside it. It covers
// exactly the records below the side's next offset, and is committed with
// that offset as its metadata, so a restart drops the same repeats a
// running differ would. Without it, a commit that lands inside a
// redelivered run on one side and not the other would turn the rest of the
// run into false missing verdicts after a restart.
type cursor struct {
	Last        uint64 `json:"last"`
	HasLast     bool   `json:"has_last,omitempty"`
	Shadowed    uint64 `json:"shadowed"`
	HasShadowed bool   `json:"has_shadowed,omitempty"`
}

// repeat reports whether r was handled already. On v1 a shadowed record is
// a repeat only of an earlier shadowed one: when signalmand restarts with
// -shadow and redelivers events it first evaluated without it, the shadowed
// copies are the ones v2 has records for, and they are compared.
func (c cursor) repeat(r *record) bool {
	if r.ev.Shadow != "" {
		return c.HasShadowed && r.ev.Seq <= c.Shadowed
	}
	return c.HasLast && r.ev.Seq <= c.Last
}

func (c *cursor) handle(r *record) {
	if !c.HasLast || r.ev.Seq > c.Last {
		c.Last, c.HasLast = r.ev.Seq, true
	}
	if r.ev.Shadow != "" {
		c.Shadowed, c.HasShadowed = r.ev.Seq, true
	}
}

// restore positions s at its committed checkpoint. A checkpoint with no
// cursor, from an older differ, starts with an empty one.
func (s *sideState) restore(cp broker.Checkpoint, log *slog.Logger) {
	s.next, s.committed = cp.Next, cp
	if cp.Meta == "" {
		return
	}
	if err := json.Unmarshal([]byte(cp.Meta), &s.cur); err != nil {
		log.Warn("differ: unreadable checkpoint metadata; starting with no repeat state", "topic", s.tp.Topic, "partition", s.tp.Partition, "err", err)
		s.cur = cursor{}
	}
}

func (s *sideState) checkpoint() broker.Checkpoint {
	b, err := json.Marshal(s.cur)
	if err != nil {
		panic(err)
	}
	return broker.Checkpoint{Next: s.next, Meta: string(b)}
}

type joiner struct {
	d     *Differ
	part  int32
	sides [2]*sideState
	tick  *time.Ticker
}

func (j *joiner) run(ctx context.Context) error {
	j.tick = time.NewTicker(j.d.cfg.CommitInterval)
	defer j.tick.Stop()
	a, b := j.sides[0], j.sides[1]
	for {
		if err := j.pull(ctx, a); err != nil {
			return err
		}
		if a.head.ev.Shadow == "" {
			j.consume(a)
			continue
		}
		gone, err := j.pullV2(ctx)
		if err != nil {
			return err
		}
		if gone {
			if err := j.emit(ctx, Compare(&a.head.ev, nil)); err != nil {
				return err
			}
			j.consume(a)
			j.d.m.Events.Inc()
			continue
		}
		h1, h2 := &a.head.ev, &b.head.ev
		switch {
		case h1.Seq == h2.Seq:
			err := j.emit(ctx, Compare(h1, h2))
			if err != nil {
				return err
			}
			j.consume(a)
			j.consume(b)
		case h1.Seq < h2.Seq:
			if err := j.emit(ctx, Compare(h1, nil)); err != nil {
				return err
			}
			j.consume(a)
		case a.cur.HasLast && h2.Seq <= a.cur.Last:
			// v1 has moved past h2's seq without a shadowed record for it,
			// so it wrote that event unshadowed (or dropped it, which v2
			// could not have evaluated). v1 has its verdict; v2's record
			// is a leftover of an attempt v1's side did not keep, not a
			// missing verdict.
			j.d.log.Debug("differ: v2 record for an event v1 wrote unshadowed", "partition", j.part, "seq", h2.Seq)
			j.consume(b)
		default:
			if err := j.emit(ctx, Compare(nil, h2)); err != nil {
				return err
			}
			j.consume(b)
		}
		j.d.m.Events.Inc()
	}
}

// pull makes sure s has a head, blocking until its reader delivers one.
// Repeats of records already handled are passed over. Offsets are
// committed while it waits, so an idle partition still checkpoints.
func (j *joiner) pull(ctx context.Context, s *sideState) error {
	for s.head == nil {
		if s.peek != nil {
			r := s.peek
			s.peek = nil
			s.head = r
			continue
		}
		select {
		case r := <-s.ch:
			if s.cur.repeat(&r) {
				s.next = r.off + 1
				continue
			}
			s.head = &r
		case <-j.tick.C:
			j.commit(ctx)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// pullV2 gets a v2 head for v1's shadowed head, or reports that v2 will
// never write one. While it waits it reads ahead on v1. A v1 record past
// the head's seq with no shadow means signalmand moved on without the v2
// lane, and v2 records are written in the same produce as their v1 record
// and before any later one, so once that record is seen, every v2 record
// for the head's seq that will ever exist is below v2's end offset. When
// the joiner has handled v2 up to that offset without finding it, it is
// missing. A shadowed v1 record past the head proves nothing yet: its own
// v2 record will resolve the head when it arrives.
func (j *joiner) pullV2(ctx context.Context) (gone bool, err error) {
	a, b := j.sides[0], j.sides[1]
	ahead := a.cur
	ahead.handle(a.head) // what v1 will have handled once head is
	proof := int64(-1)   // v2's end offset once a later unshadowed v1 record is seen
	for b.head == nil {
		if proof < 0 && a.peek != nil && a.peek.ev.Shadow == "" {
			end, err := j.d.b.EndOffsets(ctx, b.tp.Topic)
			switch {
			case err == nil:
				proof = end[b.tp.Partition]
			case ctx.Err() != nil:
				return false, ctx.Err()
			default:
				j.d.log.Warn("differ: end offsets failed; retrying", "partition", j.part, "err", err)
			}
		}
		if proof >= 0 && b.next >= proof {
			return true, nil
		}
		var v1 <-chan record
		if a.peek == nil {
			v1 = a.ch
		}
		select {
		case r := <-v1:
			if ahead.repeat(&r) {
				// A repeat once head is handled; next moves past it then.
				a.skip = r.off + 1
				continue
			}
			a.peek = &r
		case r := <-b.ch:
			if b.cur.repeat(&r) {
				b.next = r.off + 1
				continue
			}
			b.head = &r
		case <-j.tick.C:
			j.commit(ctx)
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return false, nil
}

func (j *joiner) consume(s *sideState) {
	s.cur.handle(s.head)
	s.next = max(s.head.off+1, s.skip)
	s.head = nil
}

// commit checkpoints both sides. Everything below next was compared and
// its divergences are durable, because emit returns only once they are.
// Each offset carries its side's cursor, so a restart resumes with the
// repeat state that goes with it.
func (j *joiner) commit(ctx context.Context) {
	next := map[broker.TopicPartition]broker.Checkpoint{}
	for _, s := range j.sides {
		if cp := s.checkpoint(); cp != s.committed {
			next[s.tp] = cp
		}
	}
	if len(next) == 0 {
		return
	}
	if err := j.d.b.CommitCheckpoints(ctx, j.d.cfg.Group, next); err != nil {
		j.d.log.Warn("differ: offset commit failed; the next one supersedes it", "partition", j.part, "err", err)
		return
	}
	for _, s := range j.sides {
		if cp, ok := next[s.tp]; ok {
			s.committed = cp
		}
	}
}

// emit logs, counts, and writes ds, retrying the write until it is durable
// or ctx ends.
func (j *joiner) emit(ctx context.Context, ds []Divergence) error {
	if len(ds) == 0 {
		return nil
	}
	recs := make([]broker.Record, len(ds))
	for i, d := range ds {
		b, err := json.Marshal(d)
		if err != nil {
			return err
		}
		recs[i] = broker.Record{Topic: TopicDivergences, Partition: d.Partition, Key: []byte(strconv.Itoa(int(d.Partition))), Value: b}
	}
	wait := j.d.cfg.RetryBackoff
	for {
		err := j.d.b.Produce(ctx, recs)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		j.d.log.Warn("differ: produce failed, retrying", "records", len(recs), "err", err)
		if !sleep(ctx, wait) {
			return ctx.Err()
		}
		wait = min(2*wait, 5*time.Second)
	}
	for _, d := range ds {
		j.d.m.Divergences.WithLabelValues(string(d.Class)).Inc()
		if d.Class.Counted() {
			j.d.m.Counted.Inc()
			j.d.log.LogAttrs(ctx, slog.LevelError, "divergence", d.LogAttrs()...)
		} else {
			j.d.log.LogAttrs(ctx, slog.LevelWarn, "divergence excluded", d.LogAttrs()...)
		}
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
