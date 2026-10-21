package pipe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/obs"
)

// Stage labels for signalman_stage_queue_depth. Each names the bounded
// channel feeding that stage; "batches" is the in-flight batch queue
// between ingest and the sink.
const (
	StageNormalize = "normalize"
	StageMatch     = "match"
	StageSink      = "sink"
	StageBatches   = "batches"
)

// Config sizes the pipeline. Every size is stated by the operator, never
// derived from the machine, so a load test can pin it and a result can be
// reproduced: New rejects a zero.
type Config struct {
	// Group is the events.raw consumer group.
	Group string
	// NormalizeWorkers and MatchWorkers are the worker pool sizes.
	NormalizeWorkers int
	MatchWorkers     int
	// QueueSize is the capacity of each stage channel.
	QueueSize int
	// MaxInflightBatches is how many polled batches may wait for the sink
	// beyond the one it is writing. Together with the consumer's max poll
	// size it bounds how far ingest runs ahead of the last commit.
	MaxInflightBatches int
	// RetryBackoff is the first wait after a failed produce. Waits double up
	// to 5s. Default 100ms.
	RetryBackoff time.Duration
	// SampleInterval is how often queue depth is sampled. Default 1s.
	SampleInterval time.Duration
}

func (c Config) validate() error {
	var errs []error
	if c.Group == "" {
		errs = append(errs, errors.New("group is required"))
	}
	for name, v := range map[string]int{
		"NormalizeWorkers":   c.NormalizeWorkers,
		"MatchWorkers":       c.MatchWorkers,
		"QueueSize":          c.QueueSize,
		"MaxInflightBatches": c.MaxInflightBatches,
	} {
		if v <= 0 {
			errs = append(errs, fmt.Errorf("%s must be set and positive, got %d", name, v))
		}
	}
	return errors.Join(errs...)
}

// Pipeline is ingest -> normalize -> match -> sink over one consumer group.
//
// Delivery is at-least-once. A batch is one poll's records. The sink writes
// a batch's outputs (events.norm, verdicts, alerts, drops), waits until
// every one is durable, and only then commits the batch's offsets; batches
// commit in poll order. A crash anywhere before the commit redelivers the batch. The
// redelivered records get the same Seq (it is the offset), so the
// duplicates are exact copies, which the alert sink's ReplacingMergeTree
// collapses on (partition, seq, rule_id). The other choice, commit before
// processing, turns a crash into silent loss, and loss is the one outcome a
// detection pipeline cannot report on afterwards.
//
// Every stage boundary is a bounded channel. When the sink cannot write,
// its input fills, the match and normalize workers block, the in-flight
// batch queue fills, and ingest stops polling. Consumer lag grows; nothing
// is dropped.
type Pipeline struct {
	cfg  Config
	b    broker.Broker
	in   *Ingest
	norm *Normalizer
	slot *Slot
	m    *obs.Metrics
	log  *slog.Logger

	mu        sync.Mutex
	hw        map[broker.TopicPartition]int64
	committed map[broker.TopicPartition]int64
}

// New builds a pipeline evaluating with whatever slot holds. log may be nil.
func New(cfg Config, b broker.Broker, norm *Normalizer, slot *Slot, m *obs.Metrics, log *slog.Logger) (*Pipeline, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("pipeline config: %w", err)
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 100 * time.Millisecond
	}
	if cfg.SampleInterval <= 0 {
		cfg.SampleInterval = time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Pipeline{
		cfg:       cfg,
		b:         b,
		in:        NewIngest(m),
		norm:      norm,
		slot:      slot,
		m:         m,
		log:       log,
		hw:        map[broker.TopicPartition]int64{},
		committed: map[broker.TopicPartition]int64{},
	}, nil
}

// batch is one poll. remaining is decremented by the sink goroutine only.
type batch struct {
	items     []*Item
	act       *active // read from the slot once, when the batch is formed
	remaining int
}

type work struct {
	it *Item
	b  *batch
}

// Run processes events.raw until ctx ends or a stage fails. Work that was
// not committed when it returns is redelivered to the next Run.
func (p *Pipeline) Run(ctx context.Context) error {
	cons, err := p.b.Consume(p.cfg.Group, []string{TopicEventsRaw})
	if err != nil {
		return err
	}
	defer cons.Close()
	if err := p.loadCommitted(ctx); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	normCh := make(chan work, p.cfg.QueueSize)
	matchCh := make(chan work, p.cfg.QueueSize)
	sinkCh := make(chan work, p.cfg.QueueSize)
	batchCh := make(chan *batch, p.cfg.MaxInflightBatches)

	var wg sync.WaitGroup
	wg.Go(func() { p.sample(ctx, normCh, matchCh, sinkCh, batchCh) })

	ingestErr := make(chan error, 1)
	wg.Go(func() {
		defer close(normCh)
		defer close(batchCh)
		ingestErr <- p.ingest(ctx, cons, normCh, batchCh)
	})
	pool(&wg, p.cfg.NormalizeWorkers, func() {
		for w := range normCh {
			p.norm.Normalize(w.it)
			if !send(ctx, matchCh, w) {
				return
			}
		}
	}, func() { close(matchCh) })
	pool(&wg, p.cfg.MatchWorkers, func() {
		for w := range matchCh {
			if w.it.Drop == nil {
				p.match(w.b.act.eng, w.it)
			}
			if !send(ctx, sinkCh, w) {
				return
			}
		}
	}, func() { close(sinkCh) })

	sinkErr := p.sink(ctx, cons, batchCh, sinkCh)
	cancel()
	wg.Wait()
	if err := <-ingestErr; err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return sinkErr
}

// pool starts n workers and runs done once all of them return.
func pool(wg *sync.WaitGroup, n int, worker func(), done func()) {
	var pw sync.WaitGroup
	for range n {
		pw.Go(worker)
	}
	wg.Go(func() { pw.Wait(); done() })
}

// send blocks until ch has room or ctx ends. Blocking is the backpressure.
func send[T any](ctx context.Context, ch chan<- T, v T) bool {
	select {
	case ch <- v:
		return true
	case <-ctx.Done():
		return false
	}
}

func (p *Pipeline) ingest(ctx context.Context, cons broker.Consumer, normCh chan<- work, batchCh chan<- *batch) error {
	for {
		f, err := cons.Poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			p.log.Warn("poll failed, retrying", "err", err)
			if !sleep(ctx, p.cfg.RetryBackoff) {
				return ctx.Err()
			}
			continue
		}
		p.observe(f.HighWatermarks)
		b := &batch{act: p.slot.load(), items: make([]*Item, len(f.Records)), remaining: len(f.Records)}
		for i, r := range f.Records {
			b.items[i] = p.in.Admit(r)
		}
		// The batch is queued before its items so the sink sees batches in
		// poll order. A full queue blocks here, and the consumer stops.
		if !send(ctx, batchCh, b) {
			return ctx.Err()
		}
		for _, it := range b.items {
			if !send(ctx, normCh, work{it: it, b: b}) {
				return ctx.Err()
			}
		}
	}
}

func (p *Pipeline) match(eng Engine, it *Item) {
	want := len(eng.RuleSet().Rules)
	it.Verdicts = eng.EvaluateInto(make([]event.Verdict, 0, want), it.Event)
	if len(it.Verdicts) != want {
		// Invariant 1. Writing a short verdict list would be loss the
		// audit has to find later; stopping is lag.
		panic(fmt.Sprintf("engine %s returned %d verdicts for %d rules at partition %d seq %d",
			eng.Name(), len(it.Verdicts), want, it.Event.Partition, it.Event.Seq))
	}
}

// sink completes batches in poll order: wait for every item, write the
// outputs, wait until they are durable, commit.
func (p *Pipeline) sink(ctx context.Context, cons broker.Consumer, batchCh <-chan *batch, sinkCh <-chan work) error {
	for {
		var b *batch
		select {
		case nb, ok := <-batchCh:
			if !ok {
				return ctx.Err()
			}
			b = nb
		case <-ctx.Done():
			return ctx.Err()
		}
		for b.remaining > 0 {
			select {
			case w, ok := <-sinkCh:
				if !ok {
					return ctx.Err()
				}
				w.b.remaining--
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err := p.write(ctx, b); err != nil {
			return err
		}
		p.count(b)
		p.commit(ctx, cons, b)
	}
}

// outputs builds a batch's records: events.norm, verdicts, and an alert per
// match, or a drop. Items are in poll order, which is offset order within a
// partition, so a partition's records reach every topic in Seq order, which
// is the ordering invariant for alerts.
func outputs(b *batch) []broker.Record {
	recs := make([]broker.Record, 0, 2*len(b.items))
	for _, it := range b.items {
		if it.Drop != nil {
			recs = append(recs, DropRecord(it))
			continue
		}
		recs = append(recs, NormRecord(it), VerdictRecord(b.act.eng, it))
		for _, v := range it.Verdicts {
			if v.Matched {
				r, ok := b.act.rules[v.RuleID]
				if !ok {
					panic(fmt.Sprintf("engine %s matched rule %q, which is not in its rule set", b.act.eng.Name(), v.RuleID))
				}
				recs = append(recs, AlertRecord(r, it))
			}
		}
	}
	return recs
}

// count updates the verdict and match counters for a batch that is now
// durable, so the counters never run ahead of what a consumer can read.
func (p *Pipeline) count(b *batch) {
	var matched, unmatched float64
	perRule := map[string]float64{}
	for _, it := range b.items {
		for _, v := range it.Verdicts {
			if v.Matched {
				matched++
				perRule[v.RuleID]++
			} else {
				unmatched++
			}
		}
	}
	name := b.act.eng.Name()
	p.m.Verdicts.WithLabelValues(name, "true").Add(matched)
	p.m.Verdicts.WithLabelValues(name, "false").Add(unmatched)
	for id, n := range perRule {
		p.m.RuleMatches.WithLabelValues(id).Add(n)
	}
}

// write produces a batch's outputs, retrying until they are durable or ctx
// ends. A sink that cannot write is lag, so this never gives up on its own.
func (p *Pipeline) write(ctx context.Context, b *batch) error {
	recs := outputs(b)
	wait := p.cfg.RetryBackoff
	for {
		err := p.b.Produce(ctx, recs)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p.log.Warn("produce failed, retrying the batch", "records", len(recs), "err", err)
		if !sleep(ctx, wait) {
			return ctx.Err()
		}
		wait = min(2*wait, 5*time.Second)
	}
}

// commit records the next offset for every partition in the batch. A failed
// commit is logged, not retried: the outputs are durable, the next batch's
// commit supersedes it, and the worst case is redelivery.
func (p *Pipeline) commit(ctx context.Context, cons broker.Consumer, b *batch) {
	next := map[broker.TopicPartition]int64{}
	for _, it := range b.items {
		tp := broker.TopicPartition{Topic: it.Rec.Topic, Partition: it.Rec.Partition}
		next[tp] = max(next[tp], it.Rec.Offset+1)
	}
	if err := cons.Commit(ctx, next); err != nil {
		p.log.Warn("offset commit failed; the batch will be redelivered", "err", err)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for tp, off := range next {
		p.committed[tp] = off
		p.setLag(tp)
	}
}

func (p *Pipeline) loadCommitted(ctx context.Context) error {
	c, err := p.b.CommittedOffsets(ctx, p.cfg.Group, TopicEventsRaw)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for part, off := range c {
		p.committed[broker.TopicPartition{Topic: TopicEventsRaw, Partition: part}] = off
	}
	return nil
}

func (p *Pipeline) observe(hw map[broker.TopicPartition]int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for tp, off := range hw {
		p.hw[tp] = off
		p.setLag(tp)
	}
}

// setLag is the log end minus the committed offset: records that would be
// processed again if the process died now. Caller holds p.mu.
func (p *Pipeline) setLag(tp broker.TopicPartition) {
	hw, ok := p.hw[tp]
	if !ok {
		return
	}
	p.m.ConsumerLag.WithLabelValues(tp.Topic, strconv.Itoa(int(tp.Partition))).Set(float64(max(0, hw-p.committed[tp])))
}

func (p *Pipeline) sample(ctx context.Context, normCh, matchCh, sinkCh chan work, batchCh chan *batch) {
	t := time.NewTicker(p.cfg.SampleInterval)
	defer t.Stop()
	for {
		p.m.StageQueueDepth.WithLabelValues(StageNormalize).Set(float64(len(normCh)))
		p.m.StageQueueDepth.WithLabelValues(StageMatch).Set(float64(len(matchCh)))
		p.m.StageQueueDepth.WithLabelValues(StageSink).Set(float64(len(sinkCh)))
		p.m.StageQueueDepth.WithLabelValues(StageBatches).Set(float64(len(batchCh)))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
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
