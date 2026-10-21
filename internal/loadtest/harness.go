package loadtest

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/verdict"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Config is one in-process harness: pipe.Pipeline over the in-memory
// broker, behind a Tap.
type Config struct {
	Rules    *sigma.RuleSet
	Taxonomy *sigma.Taxonomy
	// Partitions per topic. Default 8, signalmand's -partitions default.
	Partitions int32
	// MaxPoll is records per poll, which is the batch size. Default 500.
	MaxPoll int
	// Pipe sizes the pipeline. A zero Group means DefaultPipe().
	Pipe pipe.Config
	// SampleEvery is the harness's sampling period. Default 100ms.
	SampleEvery time.Duration
	// TapWorkers and TapQueue size the tap's checking pool. Default 4, 64.
	TapWorkers int
	TapQueue   int
}

// DefaultPipe is signalmand's flag defaults, so an in-process result is
// for the configuration the daemon ships with.
func DefaultPipe() pipe.Config {
	return pipe.Config{
		Group:              "signalmand",
		NormalizeWorkers:   8,
		MatchWorkers:       8,
		QueueSize:          1024,
		MaxInflightBatches: 4,
		RetryBackoff:       100 * time.Millisecond,
		SampleInterval:     50 * time.Millisecond,
	}
}

func (c Config) withDefaults() Config {
	if c.Partitions <= 0 {
		c.Partitions = 8
	}
	if c.MaxPoll <= 0 {
		c.MaxPoll = 500
	}
	if c.Pipe.Group == "" {
		c.Pipe = DefaultPipe()
	}
	if c.SampleEvery <= 0 {
		c.SampleEvery = 100 * time.Millisecond
	}
	if c.TapWorkers <= 0 {
		c.TapWorkers = 4
	}
	if c.TapQueue <= 0 {
		c.TapQueue = 64
	}
	return c
}

// Stage indexes Sample.Depth.
const (
	DepthNormalize = iota
	DepthMatch
	DepthSink
	DepthBatches
	numStages
)

// StageNames are the signalman_stage_queue_depth labels, by Depth index.
var StageNames = [numStages]string{pipe.StageNormalize, pipe.StageMatch, pipe.StageSink, pipe.StageBatches}

// Sample is the harness's view of the pipeline at one instant, read from
// the broker and from the pipeline's own metrics.
type Sample struct {
	At time.Duration `json:"at_ns"`
	// Produced is the events.raw end offset summed over partitions;
	// Committed is the group's committed offset summed the same way.
	Produced  int64 `json:"produced"`
	Committed int64 `json:"committed"`
	// PartCommitted is Committed per partition.
	PartCommitted []int64 `json:"part_committed,omitempty"`
	Ingested      float64 `json:"ingested"`
	Dropped       float64 `json:"dropped"`
	// Lag is signalman_consumer_lag_records summed over partitions.
	Lag float64 `json:"lag"`
	// Depth is signalman_stage_queue_depth per stage, by Depth index.
	Depth    [numStages]float64 `json:"depth"`
	TapQueue int                `json:"tap_queue"`
	HeapMB   float64            `json:"heap_mb"`
	NumGC    uint32             `json:"num_gc"`
	PauseMs  float64            `json:"gc_pause_total_ms"`
}

// Mark is a named instant in a run: load stopped, consumer killed.
type Mark struct {
	Name string        `json:"name"`
	At   time.Duration `json:"at_ns"`
}

// Harness runs the pipeline in process. One consumer instance runs at a
// time; Kill and Start replace it, which is a consumer crash and restart.
type Harness struct {
	cfg   Config
	Mem   *broker.Memory
	Tap   *Tap
	Reg   *prometheus.Registry
	M     *obs.Metrics
	Norm  *pipe.Normalizer
	Slot  *pipe.Slot
	start time.Time

	runMu  sync.Mutex
	cancel context.CancelFunc
	done   chan error

	fault func([]byte)

	smu         sync.Mutex
	samples     []Sample
	marks       []Mark
	stopSampler context.CancelFunc
	samplerDone chan struct{}
}

// New builds the broker, tap, metrics, normalizer, and slot, and starts
// sampling. The pipeline is not running until Start.
func New(cfg Config) (*Harness, error) {
	cfg = cfg.withDefaults()
	if cfg.Rules == nil || cfg.Taxonomy == nil {
		return nil, errors.New("loadtest: Rules and Taxonomy are required")
	}
	topics := map[string]int32{}
	for _, t := range []string{pipe.TopicEventsRaw, pipe.TopicEventsNorm, pipe.TopicVerdictsV1, pipe.TopicAlerts, pipe.TopicDrops} {
		topics[t] = cfg.Partitions
	}
	mem := broker.NewMemory(topics, broker.WithMaxPoll(cfg.MaxPoll))
	reg := prometheus.NewRegistry()
	m := obs.New(reg)
	h := &Harness{
		cfg:  cfg,
		Mem:  mem,
		Tap:  NewTap(mem, cfg.TapWorkers, cfg.TapQueue),
		Reg:  reg,
		M:    m,
		Norm: pipe.NewNormalizer(cfg.Taxonomy, pipe.NormalizeConfig{}, m),
		Slot: pipe.NewSlot(pipe.V1(cfg.Rules), m),
	}
	h.Tap.Expect(cfg.Rules)
	h.start = h.Tap.start
	ctx, cancel := context.WithCancel(context.Background())
	h.stopSampler = cancel
	h.samplerDone = make(chan struct{})
	go h.sampleLoop(ctx)
	return h, nil
}

// Config is the harness's configuration with defaults applied.
func (h *Harness) Config() Config { return h.cfg }

// Since is the time since the harness was built, the clock of every Sample,
// Mark, and LatencySample.
func (h *Harness) Since() time.Duration { return time.Since(h.start) }

// SetFault installs a normalizer fault (pipe.Normalizer.SetFault) on the
// pipeline and on ReferenceDigests' replay, so a record the fault turns
// into a drop is a drop in both. Call it before Start.
func (h *Harness) SetFault(f func([]byte)) {
	h.fault = f
	h.Norm.SetFault(f)
}

// Store reloads the slot with a v1 engine over rs; the tap is told to
// expect it first.
func (h *Harness) Store(rs *sigma.RuleSet) {
	h.Tap.Expect(rs)
	h.Slot.Store(pipe.V1(rs))
}

// Start runs a new consumer instance: a fresh pipe.Pipeline on the same
// group, broker, slot, and metrics. It resumes from the committed offsets.
func (h *Harness) Start() error {
	h.runMu.Lock()
	defer h.runMu.Unlock()
	if h.cancel != nil {
		return errors.New("loadtest: a consumer is already running")
	}
	p, err := pipe.New(h.cfg.Pipe, h.Tap, h.Norm, h.Slot, h.M, nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	h.cancel, h.done = cancel, done
	return nil
}

// Kill stops the running consumer without letting it finish anything and
// waits for it to return. Batches in flight are not committed and will be
// redelivered to the next Start.
func (h *Harness) Kill() error {
	h.runMu.Lock()
	cancel, done := h.cancel, h.done
	h.runMu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	return h.reap(done)
}

func (h *Harness) reap(done chan error) error {
	err := <-done
	h.runMu.Lock()
	if h.done == done {
		h.cancel, h.done = nil, nil
	}
	h.runMu.Unlock()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// KillAfterOutputs arms a kill at the worst moment for duplicates: when the
// n-th output batch from now has been accepted as durable and before its
// offsets are committed. The returned channel closes once the consumer has
// stopped.
func (h *Harness) KillAfterOutputs(n int) <-chan error {
	out := make(chan error, 1)
	var mu sync.Mutex
	left := n
	h.Tap.AfterOutputs(func() {
		mu.Lock()
		defer mu.Unlock()
		left--
		if left != 0 {
			return
		}
		h.Tap.AfterOutputs(nil)
		h.runMu.Lock()
		cancel, done := h.cancel, h.done
		h.runMu.Unlock()
		cancel()
		go func() { out <- h.reap(done) }()
	})
	return out
}

// Running reports whether a consumer is running.
func (h *Harness) Running() bool {
	h.runMu.Lock()
	defer h.runMu.Unlock()
	return h.cancel != nil
}

// Replay produces c into events.raw on the broker, paced by cfg.
func (h *Harness) Replay(ctx context.Context, c *Corpus, cfg ReplayConfig) (ReplayStats, error) {
	return Replay(ctx, h.Mem, c, cfg)
}

// Preload produces n records of c into events.raw as fast as the broker
// takes them, for a capacity measurement over a backlog.
func (h *Harness) Preload(c *Corpus, n int) error {
	const batch = 1000
	recs := make([]broker.Record, 0, batch)
	for i := 0; i < n; i += batch {
		recs = recs[:0]
		for j := i; j < min(n, i+batch); j++ {
			recs = append(recs, c.Records[j%len(c.Records)])
		}
		if err := h.Mem.Produce(context.Background(), recs); err != nil {
			return err
		}
	}
	return nil
}

// Mark records a named instant.
func (h *Harness) Mark(name string) {
	h.smu.Lock()
	h.marks = append(h.marks, Mark{Name: name, At: h.Since()})
	h.smu.Unlock()
}

// Produced is the events.raw end offset per partition.
func (h *Harness) Produced() map[int32]int64 {
	end, _ := h.Mem.EndOffsets(context.Background(), pipe.TopicEventsRaw)
	return end
}

// Committed is the group's committed offset per partition.
func (h *Harness) Committed() map[int32]int64 {
	c, _ := h.Mem.CommittedOffsets(context.Background(), h.cfg.Pipe.Group, pipe.TopicEventsRaw)
	return c
}

// WaitCommitted waits until every produced record is committed, and
// returns how long that took.
func (h *Harness) WaitCommitted(ctx context.Context, timeout time.Duration) (time.Duration, error) {
	t0 := time.Now()
	deadline := time.After(timeout)
	for {
		end, com := h.Produced(), h.Committed()
		done := true
		for p, e := range end {
			if com[p] < e {
				done = false
				break
			}
		}
		if done {
			return time.Since(t0), nil
		}
		select {
		case <-ctx.Done():
			return time.Since(t0), ctx.Err()
		case <-deadline:
			return time.Since(t0), fmt.Errorf("loadtest: %d of %d records committed after %v", sum(com), sum(end), timeout)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func sum(m map[int32]int64) int64 {
	var s int64
	for _, v := range m {
		s += v
	}
	return s
}

// Check accounts for every produced record (see Tap.Check).
func (h *Harness) Check() Correctness { return h.Tap.Check(h.Produced()) }

// Samples and Marks so far.
func (h *Harness) Samples() []Sample {
	h.smu.Lock()
	defer h.smu.Unlock()
	return append([]Sample(nil), h.samples...)
}

func (h *Harness) Marks() []Mark {
	h.smu.Lock()
	defer h.smu.Unlock()
	return append([]Mark(nil), h.marks...)
}

// Close stops the consumer, the sampler, and the tap.
func (h *Harness) Close() {
	_ = h.Kill()
	h.stopSampler()
	<-h.samplerDone
	h.Tap.Close()
}

func (h *Harness) sampleLoop(ctx context.Context) {
	defer close(h.samplerDone)
	t := time.NewTicker(h.cfg.SampleEvery)
	defer t.Stop()
	for {
		h.sampleOnce()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (h *Harness) sampleOnce() {
	end, com := h.Produced(), h.Committed()
	s := Sample{
		At:        h.Since(),
		Produced:  sum(end),
		Committed: sum(com),
		Ingested:  total(h.M.EventsIngested),
		Dropped:   total(h.M.EventsDropped),
		Lag:       total(h.M.ConsumerLag),
		TapQueue:  h.Tap.Queue(),
	}
	s.PartCommitted = make([]int64, h.cfg.Partitions)
	for p := range s.PartCommitted {
		s.PartCommitted[p] = com[int32(p)]
	}
	for i, name := range StageNames {
		s.Depth[i] = gauge(h.M.StageQueueDepth.WithLabelValues(name))
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.HeapMB = float64(ms.HeapAlloc) / (1 << 20)
	s.NumGC = ms.NumGC
	s.PauseMs = float64(ms.PauseTotalNs) / 1e6
	h.smu.Lock()
	h.samples = append(h.samples, s)
	h.smu.Unlock()
}

// total sums every series of a counter or gauge vector.
func total(c prometheus.Collector) float64 {
	ch := make(chan prometheus.Metric, 64)
	go func() { c.Collect(ch); close(ch) }()
	s := 0.0
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err == nil {
			s += pb.GetCounter().GetValue() + pb.GetGauge().GetValue()
		}
	}
	return s
}

func gauge(g prometheus.Gauge) float64 {
	var pb dto.Metric
	if err := g.Write(&pb); err != nil {
		return 0
	}
	return pb.GetGauge().GetValue()
}

// ReferenceDigests is what the verdict digest must be: every events.raw
// record on the broker normalized and evaluated by eng once, in offset
// order, with no pipeline, no batching, and no failures. A run whose
// deduplicated outputs give the same digests lost nothing, duplicated
// nothing it did not collapse, and reordered nothing.
func (h *Harness) ReferenceDigests(ctx context.Context, eng pipe.Engine) (map[int32]string, error) {
	end := h.Produced()
	norm := pipe.NewNormalizer(h.cfg.Taxonomy, pipe.NormalizeConfig{}, obs.New(prometheus.NewRegistry()))
	norm.SetFault(h.fault)
	in := pipe.NewIngest(obs.New(prometheus.NewRegistry()))
	out := map[int32]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	errs := make(chan error, len(end))
	for p, e := range end {
		if e == 0 {
			continue
		}
		wg.Go(func() {
			sum, err := referencePartition(ctx, h.Mem, norm, in, eng, p, e)
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			out[p] = sum
			mu.Unlock()
		})
	}
	wg.Wait()
	close(errs)
	return out, errors.Join(collect(errs)...)
}

func collect(ch chan error) []error {
	var out []error
	for e := range ch {
		out = append(out, e)
	}
	return out
}

func referencePartition(ctx context.Context, b broker.Broker, norm *pipe.Normalizer, in *pipe.Ingest, eng pipe.Engine, p int32, end int64) (string, error) {
	c, err := b.ReadFrom(map[broker.TopicPartition]int64{{Topic: pipe.TopicEventsRaw, Partition: p}: 0})
	if err != nil {
		return "", err
	}
	defer c.Close()
	d := verdict.New()
	var buf []event.Verdict
	for read := int64(0); read < end; {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		f, err := c.Poll(pctx)
		cancel()
		if err != nil {
			return "", fmt.Errorf("reference read partition %d: %w", p, err)
		}
		for _, r := range f.Records {
			if r.Offset >= end {
				continue
			}
			read++
			it := in.Admit(r)
			norm.Normalize(it)
			if it.Drop != nil {
				continue
			}
			buf = eng.EvaluateInto(buf[:0], it.Event)
			for _, v := range buf {
				if err := d.Fold(v); err != nil {
					return "", err
				}
			}
		}
	}
	return d.Sum(), nil
}

// Capacity is a measured baseline: how fast the pipeline commits a backlog.
type Capacity struct {
	Events  int           `json:"events"`
	Rules   int           `json:"rules"`
	Elapsed time.Duration `json:"elapsed_ns"`
	// Rate is events committed per second, from Start to the last commit.
	Rate float64 `json:"rate"`
	// Steady is the committed rate over the middle 80% of the run, which
	// leaves out the first poll and the last partial batches.
	Steady      float64      `json:"steady_rate"`
	Saturations []Saturation `json:"saturations"`
	Resources   Resources    `json:"resources"`
}

// MeasureCapacity preloads n records of c and times the pipeline draining
// them: the throughput with the consumer never waiting for input, which is
// the baseline every overload multiple is a multiple of.
func MeasureCapacity(ctx context.Context, cfg Config, c *Corpus, n int, timeout time.Duration) (Capacity, error) {
	h, err := New(cfg)
	if err != nil {
		return Capacity{}, err
	}
	defer h.Close()
	if err := h.Preload(c, n); err != nil {
		return Capacity{}, err
	}
	t0 := h.Since()
	if err := h.Start(); err != nil {
		return Capacity{}, err
	}
	el, err := h.WaitCommitted(ctx, timeout)
	if err != nil {
		return Capacity{}, err
	}
	if ck := h.Check(); !ck.OK() || ck.Evaluated+ck.Dropped != n {
		return Capacity{}, fmt.Errorf("loadtest: capacity run failed its own accounting: %+v", ck)
	}
	ss := h.Samples()
	t1 := t0 + el
	hc := h.Config()
	return Capacity{
		Events:      n,
		Rules:       len(cfg.Rules.Rules),
		Elapsed:     el,
		Rate:        float64(n) / el.Seconds(),
		Steady:      Throughput(ss, t0+el/10, t1-el/10),
		Saturations: Saturations(ss, hc.Pipe.QueueSize, hc.Pipe.MaxInflightBatches),
		Resources:   ResourcesOf(ss),
	}, nil
}
