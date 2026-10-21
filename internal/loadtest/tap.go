package loadtest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/pipe"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/atontalapur/signalman/internal/verdict"
)

// Tap sits between the pipeline and an in-memory broker. events.raw goes
// through to the broker, so the pipeline consumes it as usual. The output
// topics stop at the tap: each Produce call is one batch's outputs, which
// the tap accepts (that is the durable point), timestamps, and checks on a
// pool of its own goroutines, keeping a few bytes per event instead of the
// records. A 1,236-rule verdict record is about 60 KB, so keeping outputs
// in the memory broker would end an experiment by running out of memory.
//
// What it checks is invariant 1 and the reload contract, from the records
// the pipeline wrote rather than from its internals:
//   - each verdict record holds exactly one verdict per rule of its
//     RuleSetV, in the rule set's order;
//   - one Produce call (one batch) never holds two RuleSetV values;
//   - the call's alerts are exactly its matched verdicts;
//   - every events.raw offset ends with verdicts or a drop, not both and not
//     neither (Check).
//
// It also injects the failures the experiments need: an output outage, a
// hook after a batch's outputs are durable but before its commit, and
// partitions whose records the consumer cannot fetch.
type Tap struct {
	broker.Broker
	now   func() time.Time
	start time.Time

	work    chan tapCall
	pending sync.WaitGroup
	workers sync.WaitGroup

	outage       atomic.Bool
	outageErrors atomic.Int64

	hookMu sync.Mutex
	after  func()

	offMu   sync.Mutex
	offline map[int32]bool

	mu       sync.Mutex
	versions map[string]*version
	byIdx    []*version
	parts    map[int32]map[uint64]*outcome
	lat      []LatencySample
	st       tapStats
	problems []string
}

type tapStats struct {
	calls, verdictRecs, dupVerdictRecs, alertRecs, dupAlerts         int
	dropRecs, dupDropRecs, straddles, shortVerdicts, alertMismatches int
	redeliveryChanged, slowParses                                    int
}

type version struct {
	idx    int
	rs     *sigma.RuleSet
	ids    map[string]int
	prefix [][]byte // the exact bytes encoding/json writes before each matched flag
}

type outcome struct {
	ver         int // index into byIdx; -1 for a drop
	matched     []int
	reason      string
	verdictRecs int
	dropRecs    int
}

// LatencySample is one event's end-to-end latency: from the events.raw
// produce (the record timestamp the broker assigned) to the moment its
// outputs were accepted as durable. At is when that happened, measured from
// the tap's creation.
type LatencySample struct {
	At        time.Duration
	Lat       time.Duration
	Partition int32
}

type tapCall struct {
	recs []broker.Record
	at   time.Time
}

var errOutage = errors.New("loadtest: injected output outage")

// NewTap wraps b. workers sizes the checking pool and queue the number of
// accepted calls that may wait for it; when the pool falls behind, Produce
// blocks, which the pipeline sees as a slow sink. Both are reported, so a
// result limited by the tap reads as one.
func NewTap(b broker.Broker, workers, queue int) *Tap {
	t := &Tap{
		Broker:   b,
		now:      time.Now,
		work:     make(chan tapCall, queue),
		offline:  map[int32]bool{},
		versions: map[string]*version{},
		parts:    map[int32]map[uint64]*outcome{},
	}
	t.start = t.now()
	for range workers {
		t.workers.Go(func() {
			for c := range t.work {
				t.process(c)
				t.pending.Done()
			}
		})
	}
	return t
}

// Expect registers a rule set the pipeline may evaluate with. A verdict
// record under an unregistered RuleSetV is a problem.
func (t *Tap) Expect(rs *sigma.RuleSet) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.versions[rs.Version]; ok {
		return
	}
	v := &version{idx: len(t.byIdx), rs: rs, ids: make(map[string]int, len(rs.Rules))}
	for i, r := range rs.Rules {
		v.ids[r.ID] = i
		id, _ := json.Marshal(r.ID)
		p := []byte(`{"rule_id":`)
		if i > 0 {
			p = []byte(`,{"rule_id":`)
		}
		p = append(p, id...)
		p = append(p, `,"matched":`...)
		v.prefix = append(v.prefix, p)
	}
	t.versions[rs.Version] = v
	t.byIdx = append(t.byIdx, v)
}

// SetOutage makes every output Produce fail while on.
func (t *Tap) SetOutage(on bool) { t.outage.Store(on) }

// OutageErrors is how many output Produce calls the outage refused.
func (t *Tap) OutageErrors() int64 { return t.outageErrors.Load() }

// AfterOutputs sets a hook run synchronously each time a batch's outputs
// are accepted, before Produce returns and so before the batch's offsets
// are committed. Cancelling the pipeline from it is a kill at the worst
// moment for duplicates. nil clears it.
func (t *Tap) AfterOutputs(f func()) {
	t.hookMu.Lock()
	t.after = f
	t.hookMu.Unlock()
}

// SetOffline makes partition p of events.raw unfetchable, or fetchable
// again, for every consumer the tap hands out. Records the consumer reads
// while p is offline are held back and released in order once it is online,
// which is what a partition whose leader is away looks like to a consumer.
func (t *Tap) SetOffline(p int32, off bool) {
	t.offMu.Lock()
	t.offline[p] = off
	t.offMu.Unlock()
}

func (t *Tap) isOffline(p int32) bool {
	t.offMu.Lock()
	defer t.offMu.Unlock()
	return t.offline[p]
}

// Queue is how many accepted output calls wait for the checking pool.
func (t *Tap) Queue() int { return len(t.work) }

// Flush waits until every accepted call has been checked.
func (t *Tap) Flush() { t.pending.Wait() }

// Close flushes and stops the checking pool.
func (t *Tap) Close() {
	t.Flush()
	close(t.work)
	t.workers.Wait()
}

func (t *Tap) Produce(ctx context.Context, recs []broker.Record) error {
	if len(recs) == 0 {
		return nil
	}
	if recs[0].Topic == pipe.TopicEventsRaw {
		return t.Broker.Produce(ctx, recs)
	}
	if t.outage.Load() {
		t.outageErrors.Add(1)
		return errOutage
	}
	c := tapCall{recs: recs, at: t.now()}
	t.pending.Add(1)
	select {
	case t.work <- c:
	case <-ctx.Done():
		t.pending.Done()
		return ctx.Err()
	}
	t.hookMu.Lock()
	h := t.after
	t.hookMu.Unlock()
	if h != nil {
		h()
	}
	return nil
}

func (t *Tap) Consume(group string, topics []string) (broker.Consumer, error) {
	c, err := t.Broker.Consume(group, topics)
	if err != nil {
		return nil, err
	}
	return &tapConsumer{Consumer: c, t: t}, nil
}

// tapConsumer withholds records of offline partitions.
type tapConsumer struct {
	broker.Consumer
	t    *Tap
	held []broker.Record
}

// releaseMax caps one Poll of held records, so a partition coming back
// online does not turn into one unbounded batch.
const releaseMax = 500

func (c *tapConsumer) Poll(ctx context.Context) (broker.Fetch, error) {
	for {
		if f, ok := c.release(); ok {
			return f, nil
		}
		pctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		f, err := c.Consumer.Poll(pctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return broker.Fetch{}, ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			return f, err
		}
		kept := f.Records[:0:0]
		for _, r := range f.Records {
			if c.t.isOffline(r.Partition) {
				c.held = append(c.held, r)
			} else {
				kept = append(kept, r)
			}
		}
		if len(kept) > 0 {
			f.Records = kept
			return f, nil
		}
	}
}

// release returns held records of partitions that are online again, in the
// order they were read, at most releaseMax at a time.
func (c *tapConsumer) release() (broker.Fetch, bool) {
	if len(c.held) == 0 {
		return broker.Fetch{}, false
	}
	// A partition's records must leave in offset order: once one of its
	// records is kept back, every later one is too.
	stop := map[int32]bool{}
	var out, keep []broker.Record
	for _, r := range c.held {
		if !stop[r.Partition] && len(out) < releaseMax && !c.t.isOffline(r.Partition) {
			out = append(out, r)
		} else {
			stop[r.Partition] = true
			keep = append(keep, r)
		}
	}
	if len(out) == 0 {
		return broker.Fetch{}, false
	}
	c.held = keep
	return broker.Fetch{Records: out, HighWatermarks: map[broker.TopicPartition]int64{}}, true
}

// Parsed forms of the output records. Only the fields the checks need.
type verdictHead struct {
	Partition int32  `json:"partition"`
	Seq       uint64 `json:"seq"`
	RuleSetV  string `json:"ruleset_v"`
}

type normHead struct {
	Partition int32     `json:"partition"`
	Seq       uint64    `json:"seq"`
	IngestAt  time.Time `json:"ingest_at"`
}

type alertKey struct {
	Partition int32  `json:"partition"`
	Seq       uint64 `json:"seq"`
	RuleID    string `json:"rule_id"`
}

type parsedVerdict struct {
	head    verdictHead
	ver     *version
	matched []int
}

var (
	sepVerdicts = []byte(`,"verdicts":[`)
	sepFields   = []byte(`,"fields":`)
	sepTitle    = []byte(`,"rule_title":`)
)

// head unmarshals the leading fields of a record written by encoding/json,
// up to sep, without scanning the rest.
func head(b, sep []byte, v any) error {
	i := bytes.Index(b, sep)
	if i < 0 {
		return json.Unmarshal(b, v)
	}
	h := make([]byte, 0, i+1)
	h = append(append(h, b[:i]...), '}')
	return json.Unmarshal(h, v)
}

func (t *Tap) version(v string) *version {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.versions[v]
}

// parseVerdict reads a verdict record. The fast path walks the bytes
// encoding/json writes for the expected rule list; anything else falls
// back to a full decode, and is still checked.
func (t *Tap) parseVerdict(b []byte) (parsedVerdict, string) {
	var pv parsedVerdict
	if err := head(b, sepVerdicts, &pv.head); err != nil {
		return pv, fmt.Sprintf("verdict record does not decode: %v", err)
	}
	pv.ver = t.version(pv.head.RuleSetV)
	if pv.ver == nil {
		return pv, fmt.Sprintf("partition %d seq %d: verdicts under unregistered ruleset_v %q", pv.head.Partition, pv.head.Seq, pv.head.RuleSetV)
	}
	if m, ok := fastVerdicts(b, pv.ver); ok {
		pv.matched = m
		return pv, ""
	}
	t.mu.Lock()
	t.st.slowParses++
	t.mu.Unlock()
	var full pipe.EventVerdicts
	if err := json.Unmarshal(b, &full); err != nil {
		return pv, fmt.Sprintf("verdict record does not decode: %v", err)
	}
	rules := pv.ver.rs.Rules
	if len(full.Verdicts) != len(rules) {
		return pv, fmt.Sprintf("short:partition %d seq %d: %d verdicts for %d rules", full.Partition, full.Seq, len(full.Verdicts), len(rules))
	}
	for i, v := range full.Verdicts {
		if v.RuleID != rules[i].ID {
			return pv, fmt.Sprintf("short:partition %d seq %d: verdict %d is rule %q, want %q", full.Partition, full.Seq, i, v.RuleID, rules[i].ID)
		}
		if v.Matched {
			pv.matched = append(pv.matched, i)
		}
	}
	return pv, ""
}

func fastVerdicts(b []byte, v *version) ([]int, bool) {
	i := bytes.Index(b, sepVerdicts)
	if i < 0 {
		return nil, false
	}
	rest := b[i+len(sepVerdicts):]
	var matched []int
	for k, p := range v.prefix {
		if !bytes.HasPrefix(rest, p) {
			return nil, false
		}
		rest = rest[len(p):]
		switch {
		case bytes.HasPrefix(rest, []byte("true}")):
			matched = append(matched, k)
			rest = rest[5:]
		case bytes.HasPrefix(rest, []byte("false}")):
			rest = rest[6:]
		default:
			return nil, false
		}
	}
	return matched, bytes.Equal(rest, []byte("]}"))
}

func (t *Tap) problem(s string) {
	if len(t.problems) < 20 {
		t.problems = append(t.problems, s)
	}
}

func (t *Tap) process(c tapCall) {
	var (
		verdicts []parsedVerdict
		drops    []pipe.DropEntry
		alerts   = map[alertKey]int{}
		norms    int
		lats     []LatencySample
		probs    []string
		short    int
	)
	at := c.at.Sub(t.start)
	for _, r := range c.recs {
		switch r.Topic {
		case pipe.TopicVerdictsV1:
			pv, p := t.parseVerdict(r.Value)
			if p != "" {
				if len(p) > 6 && p[:6] == "short:" {
					short++
					p = p[6:]
				}
				probs = append(probs, p)
				continue
			}
			verdicts = append(verdicts, pv)
		case pipe.TopicEventsNorm:
			var h normHead
			if err := head(r.Value, sepFields, &h); err != nil {
				probs = append(probs, fmt.Sprintf("events.norm record does not decode: %v", err))
				continue
			}
			norms++
			lats = append(lats, LatencySample{At: at, Lat: c.at.Sub(h.IngestAt), Partition: h.Partition})
		case pipe.TopicAlerts:
			var k alertKey
			if err := head(r.Value, sepTitle, &k); err != nil {
				probs = append(probs, fmt.Sprintf("alert record does not decode: %v", err))
				continue
			}
			alerts[k]++
		case pipe.TopicDrops:
			var d pipe.DropEntry
			if err := json.Unmarshal(r.Value, &d); err != nil {
				probs = append(probs, fmt.Sprintf("drop record does not decode: %v", err))
				continue
			}
			drops = append(drops, d)
		default:
			probs = append(probs, fmt.Sprintf("output to unexpected topic %q", r.Topic))
		}
	}

	vers := map[string]bool{}
	want := map[alertKey]int{}
	nAlerts := 0
	for _, pv := range verdicts {
		vers[pv.head.RuleSetV] = true
		for _, i := range pv.matched {
			want[alertKey{pv.head.Partition, pv.head.Seq, pv.ver.rs.Rules[i].ID}]++
		}
	}
	mismatch := len(want) != len(alerts)
	for k, n := range alerts {
		nAlerts += n
		if want[k] != n {
			mismatch = true
		}
	}
	if norms != len(verdicts) {
		probs = append(probs, fmt.Sprintf("batch has %d events.norm records for %d verdict records", norms, len(verdicts)))
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.st.calls++
	t.st.shortVerdicts += short
	for _, p := range probs {
		t.problem(p)
	}
	if len(vers) > 1 {
		t.st.straddles++
		t.problem(fmt.Sprintf("one batch holds verdicts under %d rule set versions", len(vers)))
	}
	if mismatch {
		t.st.alertMismatches++
		t.problem(fmt.Sprintf("batch alerts %d records do not match its matched verdicts", nAlerts))
	}
	t.st.alertRecs += nAlerts
	t.lat = append(t.lat, lats...)
	for _, pv := range verdicts {
		o := t.at(pv.head.Partition, pv.head.Seq)
		if o.verdictRecs > 0 {
			if o.ver == pv.ver.idx && equalInts(o.matched, pv.matched) {
				t.st.dupVerdictRecs++
				t.st.dupAlerts += len(pv.matched)
			} else {
				t.st.redeliveryChanged++
			}
		} else {
			o.ver, o.matched = pv.ver.idx, pv.matched
		}
		o.verdictRecs++
		t.st.verdictRecs++
	}
	for _, d := range drops {
		o := t.at(d.Partition, d.Seq)
		if o.dropRecs > 0 {
			t.st.dupDropRecs++
		} else if o.verdictRecs == 0 {
			o.ver = -1
		}
		o.reason = d.Reason
		o.dropRecs++
		t.st.dropRecs++
	}
}

func (t *Tap) at(p int32, s uint64) *outcome {
	m := t.parts[p]
	if m == nil {
		m = map[uint64]*outcome{}
		t.parts[p] = m
	}
	o := m[s]
	if o == nil {
		o = &outcome{ver: -1}
		m[s] = o
	}
	return o
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Latencies returns every end-to-end latency sample so far, in the order
// the checking pool recorded them.
func (t *Tap) Latencies() []LatencySample {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]LatencySample(nil), t.lat...)
}

// Correctness is what the outputs say about invariant 1 and the reload
// contract, over every events.raw offset below the end offsets checked.
type Correctness struct {
	Events      int            `json:"events"`
	Evaluated   int            `json:"evaluated"`
	Dropped     int            `json:"dropped"`
	DropReasons map[string]int `json:"drop_reasons,omitempty"`
	// Missing offsets have neither verdicts nor a drop; Both have both.
	Missing int `json:"missing"`
	Both    int `json:"both"`
	// Beyond counts outputs for offsets at or above the end offsets.
	Beyond int `json:"beyond"`
	// Matched counts distinct (event, rule) matches: the alert table after
	// ReplacingMergeTree collapses duplicates.
	Matched int `json:"matched"`
	// AlertRecords counts alert records as written, duplicates included.
	AlertRecords int `json:"alert_records"`
	// DuplicateVerdictRecords and DuplicateAlerts are redelivered copies,
	// identical to the first write.
	DuplicateVerdictRecords int `json:"duplicate_verdict_records"`
	DuplicateAlerts         int `json:"duplicate_alerts"`
	DuplicateDrops          int `json:"duplicate_drops"`
	// RedeliveryChanged counts redelivered events whose verdicts differ
	// from the first write: possible only when a reload landed between the
	// two writes.
	RedeliveryChanged int `json:"redelivery_changed"`
	Straddles         int `json:"straddles"`
	ShortVerdicts     int `json:"short_verdicts"`
	AlertMismatches   int `json:"alert_mismatches"`
	SlowParses        int `json:"slow_parses"`
	OutputCalls       int `json:"output_calls"`
	// EventsByVersion counts evaluated events per RuleSetV.
	EventsByVersion map[string]int `json:"events_by_version"`
	// Digests is the verdict digest per partition, each event counted once.
	Digests  map[int32]string `json:"digests"`
	Problems []string         `json:"problems,omitempty"`
}

// OK reports whether invariant 1 and the reload contract held.
func (c Correctness) OK() bool {
	return c.Missing == 0 && c.Both == 0 && c.Beyond == 0 && c.Straddles == 0 &&
		c.ShortVerdicts == 0 && c.AlertMismatches == 0 && len(c.Problems) == 0
}

// Check flushes and accounts for every offset below end, per partition.
func (t *Tap) Check(end map[int32]int64) Correctness {
	t.Flush()
	t.mu.Lock()
	defer t.mu.Unlock()
	c := Correctness{
		DropReasons:             map[string]int{},
		EventsByVersion:         map[string]int{},
		Digests:                 map[int32]string{},
		AlertRecords:            t.st.alertRecs,
		DuplicateVerdictRecords: t.st.dupVerdictRecs,
		DuplicateAlerts:         t.st.dupAlerts,
		DuplicateDrops:          t.st.dupDropRecs,
		RedeliveryChanged:       t.st.redeliveryChanged,
		Straddles:               t.st.straddles,
		ShortVerdicts:           t.st.shortVerdicts,
		AlertMismatches:         t.st.alertMismatches,
		SlowParses:              t.st.slowParses,
		OutputCalls:             t.st.calls,
		Problems:                append([]string(nil), t.problems...),
	}
	parts := make([]int32, 0, len(end))
	for p := range end {
		parts = append(parts, p)
	}
	for p := range t.parts {
		if _, ok := end[p]; !ok {
			parts = append(parts, p)
		}
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i] < parts[j] })
	for _, p := range parts {
		e := end[p]
		m := t.parts[p]
		d := verdict.New()
		for s := range m {
			if int64(s) >= e {
				c.Beyond++
			}
		}
		for s := uint64(0); int64(s) < e; s++ {
			c.Events++
			o := m[s]
			switch {
			case o == nil:
				c.Missing++
				continue
			case o.verdictRecs > 0 && o.dropRecs > 0:
				c.Both++
				continue
			case o.dropRecs > 0:
				c.Dropped++
				c.DropReasons[o.reason]++
				continue
			}
			c.Evaluated++
			v := t.byIdx[o.ver]
			c.EventsByVersion[v.rs.Version]++
			c.Matched += len(o.matched)
			k := 0
			for i, r := range v.rs.Rules {
				hit := k < len(o.matched) && o.matched[k] == i
				if hit {
					k++
				}
				_ = d.Fold(event.Verdict{Seq: s, Partition: p, RuleID: r.ID, Matched: hit})
			}
		}
		if e > 0 {
			c.Digests[p] = d.Sum()
		}
	}
	return c
}
