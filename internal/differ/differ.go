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
	// Primary is the serving engine, whose records name the shadow they
	// were evaluated beside and so drive the join: "v1" (the default) while
	// v1 serves, "v2" once v2 serves and v1 shadows as the oracle.
	// Divergence classes stay relative to v1 either way.
	Primary string
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
// A primary record names the shadow it was evaluated alongside. A primary
// record with no shadow owes no shadow record and is passed over without
// waiting. The primary is v1 unless Config.Primary says v2.
//
// Divergence records are produced before the offsets that cover them are
// committed, so a restart repeats work rather than skipping it. The
// repeat-dropping state starts empty after a restart, so a redelivered
// batch that straddles the committed offset can be compared twice; a
// divergence written twice carries the same (partition, seq, rule_id).
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
	switch cfg.Primary {
	case "":
		cfg.Primary = v1.Name
	case v1.Name, v2.Name:
	default:
		return nil, fmt.Errorf("differ: primary %q, want %s or %s", cfg.Primary, v1.Name, v2.Name)
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
	start := map[string]map[int32]int64{}
	for _, t := range []string{pipe.TopicVerdictsV1, pipe.TopicVerdictsV2} {
		if start[t], err = d.b.CommittedOffsets(ctx, d.cfg.Group, t); err != nil {
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
		j := &joiner{d: d, part: p, primary: primaryIndex(d.cfg.Primary),
			sides: [2]*sideState{
				{ch: a, tp: broker.TopicPartition{Topic: pipe.TopicVerdictsV1, Partition: p}, next: start[pipe.TopicVerdictsV1][p]},
				{ch: b, tp: broker.TopicPartition{Topic: pipe.TopicVerdictsV2, Partition: p}, next: start[pipe.TopicVerdictsV2][p]},
			}}
		for i, s := range j.sides {
			s.committed = s.next
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
	ch        <-chan record
	tp        broker.TopicPartition
	head      *record
	last      uint64 // highest seq taken as a head
	started   bool
	next      int64 // offset after the last record fully handled
	committed int64
}

type joiner struct {
	d     *Differ
	part  int32
	sides [2]*sideState // v1, v2
	// primary indexes the side whose records drive the join.
	primary int
	tick    *time.Ticker
}

func primaryIndex(name string) int {
	if name == v2.Name {
		return 1
	}
	return 0
}

// compare classifies one event from the primary's and the shadow's record,
// either of which may be nil, in Compare's v1, v2 order.
func (j *joiner) compare(p, sh *pipe.EventVerdicts) []Divergence {
	if j.primary == 1 {
		return Compare(sh, p)
	}
	return Compare(p, sh)
}

func (j *joiner) run(ctx context.Context) error {
	j.tick = time.NewTicker(j.d.cfg.CommitInterval)
	defer j.tick.Stop()
	a, b := j.sides[j.primary], j.sides[1-j.primary]
	for {
		if err := j.pull(ctx, a); err != nil {
			return err
		}
		if a.head.ev.Shadow == "" {
			j.consume(a)
			continue
		}
		if err := j.pull(ctx, b); err != nil {
			return err
		}
		h1, h2 := &a.head.ev, &b.head.ev
		switch {
		case h1.Seq == h2.Seq:
			err := j.emit(ctx, j.compare(h1, h2))
			if err != nil {
				return err
			}
			j.consume(a)
			j.consume(b)
		case h1.Seq < h2.Seq:
			if err := j.emit(ctx, j.compare(h1, nil)); err != nil {
				return err
			}
			j.consume(a)
		default:
			if err := j.emit(ctx, j.compare(nil, h2)); err != nil {
				return err
			}
			j.consume(b)
		}
		j.d.m.Events.Inc()
	}
}

// pull makes sure s has a head, blocking until its reader delivers one.
// Records at or below the side's last head are redelivery repeats: they
// were compared already and are passed over. Offsets are committed while
// it waits, so an idle partition still checkpoints.
func (j *joiner) pull(ctx context.Context, s *sideState) error {
	for s.head == nil {
		select {
		case r := <-s.ch:
			if s.started && r.ev.Seq <= s.last {
				s.next = r.off + 1
				continue
			}
			s.head, s.last, s.started = &r, r.ev.Seq, true
		case <-j.tick.C:
			j.commit(ctx)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (j *joiner) consume(s *sideState) {
	s.next = s.head.off + 1
	s.head = nil
}

// commit checkpoints both sides. Everything below next was compared and
// its divergences are durable, because emit returns only once they are.
func (j *joiner) commit(ctx context.Context) {
	next := map[broker.TopicPartition]int64{}
	for _, s := range j.sides {
		if s.next != s.committed {
			next[s.tp] = s.next
		}
	}
	if len(next) == 0 {
		return
	}
	if err := j.d.b.CommitOffsets(ctx, j.d.cfg.Group, next); err != nil {
		j.d.log.Warn("differ: offset commit failed; the next one supersedes it", "partition", j.part, "err", err)
		return
	}
	for _, s := range j.sides {
		s.committed = s.next
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
