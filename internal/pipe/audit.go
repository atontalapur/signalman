package pipe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/obs"
)

// ErrInvariant is wrapped by every audit failure: an admitted event that
// left neither verdicts nor a drop, left both, or left fewer verdicts than
// its rule set has rules.
var ErrInvariant = errors.New("invariant 1 violated")

// AuditConfig configures the audit.
type AuditConfig struct {
	// Group is the pipeline's events.raw consumer group.
	Group string
	// VerdictTopic is the engine's verdict topic. Default verdicts.v1.
	VerdictTopic string
	// Window is the widest seq range checked as one window. Default 10000.
	Window int64
	// ReadTimeout bounds how long a step waits to read the output topics up
	// to their end offsets. Default 10s.
	ReadTimeout time.Duration
}

// WindowReport is one partition's seq range [From, To) and its arithmetic.
// Ingested is To - From: every offset below the committed offset is an
// admitted event (see Auditor).
type WindowReport struct {
	Partition int32
	From, To  int64
	Ingested  int64
	Evaluated int64 // events with a complete verdict record
	Verdicts  int64 // sum of their rule counts
	Dropped   int64
	// Missing, Both, and Short are the violations.
	Missing, Both, Short int64
	Examples             []string
}

// OK reports whether ingested == evaluated + dropped with nothing left over.
func (w WindowReport) OK() bool {
	return w.Missing == 0 && w.Both == 0 && w.Short == 0 && w.Ingested == w.Evaluated+w.Dropped
}

func (w WindowReport) String() string {
	s := fmt.Sprintf("partition %d seqs [%d,%d): %d ingested, %d evaluated (%d verdicts) + %d dropped",
		w.Partition, w.From, w.To, w.Ingested, w.Evaluated, w.Verdicts, w.Dropped)
	if !w.OK() {
		s += fmt.Sprintf("; %d missing, %d both, %d short: %s", w.Missing, w.Both, w.Short, strings.Join(w.Examples, "; "))
	}
	return s
}

// seen is what the output topics said about one seq.
type seen struct {
	verdicts, drops int
	short           string // why a verdict record was incomplete, if one was
	rules           int64
}

// Auditor checks invariant 1 against what is durable: for every events.raw
// offset the pipeline has committed, the verdict topic holds a record with
// one verdict per rule, or the drops topic holds an entry, and not both.
// Because the pipeline commits only after its outputs are durable, the
// arithmetic must close for every committed offset; an event the pipeline
// lost shows up as a missing seq, never as an in-flight one.
//
// It reads the output topics, not the pipeline's memory, so it checks the
// pipeline rather than restating it. Windows slide forward with the
// committed offset, at most Window seqs at a time; only seqs at or above the
// current floor are held, so memory is bounded by how far outputs run ahead
// of commits.
//
// Assumptions, stated so a violation of them reads as one:
//   - events.raw is a plain topic: offsets below the committed offset are
//     dense, so To - From is the ingested count. A transactional or
//     compacted events.raw would make the audit report missing seqs.
//   - Offsets below the log start of events.raw at construction were never
//     admitted (retention removed them), so the audit starts at
//     max(committed, log start) per partition.
//   - The auditor starts before any pipeline it audits produces, in the
//     same process as signalmand. It reads outputs from the end offsets at
//     construction and audits from the committed offset at construction;
//     every seq at or above that offset is (re)processed after it starts.
//     Two signalmand instances on one group would break this.
type Auditor struct {
	b      broker.Broker
	cfg    AuditConfig
	counts func(rulesetV string) (int, bool)
	m      *obs.Metrics
	log    *slog.Logger

	out   broker.Consumer
	pos   map[broker.TopicPartition]int64
	floor map[int32]int64
	seen  map[int32]map[uint64]*seen
}

// NewAuditor snapshots where to start. counts returns how many verdicts
// per event a rule set version owes; Slot.RuleCount is the usual source.
func NewAuditor(ctx context.Context, b broker.Broker, cfg AuditConfig, counts func(string) (int, bool), m *obs.Metrics, log *slog.Logger) (*Auditor, error) {
	if cfg.Group == "" {
		return nil, errors.New("audit: group is required")
	}
	if cfg.VerdictTopic == "" {
		cfg.VerdictTopic = TopicVerdictsV1
	}
	if cfg.Window <= 0 {
		cfg.Window = 10000
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	a := &Auditor{
		b: b, cfg: cfg, counts: counts, m: m, log: log,
		pos:   map[broker.TopicPartition]int64{},
		floor: map[int32]int64{},
		seen:  map[int32]map[uint64]*seen{},
	}
	// Output end offsets first, then the committed offsets: anything at or
	// above the committed offset is produced again after this point.
	for _, t := range []string{cfg.VerdictTopic, TopicDrops} {
		end, err := b.EndOffsets(ctx, t)
		if err != nil {
			return nil, err
		}
		for p, off := range end {
			a.pos[broker.TopicPartition{Topic: t, Partition: p}] = off
		}
	}
	c, err := b.CommittedOffsets(ctx, cfg.Group, TopicEventsRaw)
	if err != nil {
		return nil, err
	}
	// The floor is the committed offset, or the log start if that is later:
	// offsets retention removed were never admitted, so they cannot be
	// missing. A partition with no commit starts at its log start, not 0.
	logStart, err := b.StartOffsets(ctx, TopicEventsRaw)
	if err != nil {
		return nil, err
	}
	for p, off := range logStart {
		a.floor[p] = off
	}
	for p, off := range c {
		if off < a.floor[p] {
			log.Warn("audit: committed offset is below the log start; records were removed before the pipeline read them",
				"partition", p, "committed", off, "log_start", a.floor[p])
			continue
		}
		a.floor[p] = off
	}
	start := make(map[broker.TopicPartition]int64, len(a.pos))
	for tp, off := range a.pos {
		start[tp] = off
	}
	a.out, err = b.ReadFrom(start)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Close releases the output reader.
func (a *Auditor) Close() { a.out.Close() }

// Step audits everything committed since the last step. It returns the
// windows it closed and, if any failed, an error wrapping ErrInvariant that
// names the events.
func (a *Auditor) Step(ctx context.Context) ([]WindowReport, error) {
	committed, err := a.b.CommittedOffsets(ctx, a.cfg.Group, TopicEventsRaw)
	if err != nil {
		return nil, err
	}
	// Every output for a seq below committed was durable before the commit,
	// so it is below these end offsets.
	if err := a.readToEnd(ctx); err != nil {
		return nil, err
	}

	parts := make([]int32, 0, len(committed))
	for p := range committed {
		parts = append(parts, p)
	}
	slices.Sort(parts)

	var reports []WindowReport
	var failed []string
	for _, p := range parts {
		for a.floor[p] < committed[p] {
			lo := a.floor[p]
			hi := min(committed[p], lo+a.cfg.Window)
			w := a.close(p, lo, hi)
			reports = append(reports, w)
			if !w.OK() {
				failed = append(failed, w.String())
				a.m.AuditViolations.WithLabelValues(strconv.Itoa(int(p))).Add(float64(w.Missing + w.Both + w.Short))
				a.log.Error("invariant 1 violated: admitted events are unaccounted for", "window", w.String())
			}
		}
	}
	if len(failed) > 0 {
		return reports, fmt.Errorf("%w: %s", ErrInvariant, strings.Join(failed, " | "))
	}
	return reports, nil
}

// Run steps every interval until ctx ends. A failing window is logged at
// error level and counted; the audit keeps going, so the next window is
// still checked.
func (a *Auditor) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := a.Step(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, ErrInvariant) {
			a.log.Warn("audit step failed", "err", err)
		}
	}
}

func (a *Auditor) readToEnd(ctx context.Context) error {
	want := map[broker.TopicPartition]int64{}
	for _, t := range []string{a.cfg.VerdictTopic, TopicDrops} {
		end, err := a.b.EndOffsets(ctx, t)
		if err != nil {
			return err
		}
		for p, off := range end {
			tp := broker.TopicPartition{Topic: t, Partition: p}
			if off > a.pos[tp] {
				want[tp] = off
			}
		}
	}
	rctx, cancel := context.WithTimeout(ctx, a.cfg.ReadTimeout)
	defer cancel()
	for len(want) > 0 {
		f, err := a.out.Poll(rctx)
		if err != nil {
			return fmt.Errorf("audit: reading outputs: %w", err)
		}
		for _, r := range f.Records {
			tp := broker.TopicPartition{Topic: r.Topic, Partition: r.Partition}
			a.pos[tp] = r.Offset + 1
			a.record(r)
			if end, ok := want[tp]; ok && a.pos[tp] >= end {
				delete(want, tp)
			}
		}
	}
	return nil
}

func (a *Auditor) at(p int32, s uint64) *seen {
	if uint64(a.floor[p]) > s {
		return nil // already audited; a late redelivery duplicate
	}
	m := a.seen[p]
	if m == nil {
		m = map[uint64]*seen{}
		a.seen[p] = m
	}
	o := m[s]
	if o == nil {
		o = &seen{}
		m[s] = o
	}
	return o
}

func (a *Auditor) record(r broker.Record) {
	if r.Topic == TopicDrops {
		var d DropEntry
		if err := json.Unmarshal(r.Value, &d); err != nil {
			a.log.Error("audit: unreadable drop entry", "offset", r.Offset, "err", err)
			return
		}
		if o := a.at(d.Partition, d.Seq); o != nil {
			o.drops++
		}
		return
	}
	var ev EventVerdicts
	if err := json.Unmarshal(r.Value, &ev); err != nil {
		a.log.Error("audit: unreadable verdict record", "offset", r.Offset, "err", err)
		return
	}
	o := a.at(ev.Partition, ev.Seq)
	if o == nil {
		return
	}
	o.verdicts++
	// The count is checked, not the rule ids: v1 and v2 owe one verdict per
	// rule, and a per-record set over 1,500 ids would cost more than the
	// evaluation it audits. A duplicated id with the right count is the
	// differ's to find.
	want, ok := a.counts(ev.RuleSetV)
	switch {
	case !ok:
		o.short = fmt.Sprintf("seq %d: rule set %q was never loaded", ev.Seq, ev.RuleSetV)
	case len(ev.Verdicts) != want:
		o.short = fmt.Sprintf("seq %d: %d verdicts for %d rules under %s", ev.Seq, len(ev.Verdicts), want, ev.RuleSetV)
	default:
		o.rules = int64(want)
	}
}

// close checks [lo, hi) on partition p, forgets it, and advances the floor.
func (a *Auditor) close(p int32, lo, hi int64) WindowReport {
	w := WindowReport{Partition: p, From: lo, To: hi, Ingested: hi - lo}
	example := func(s string) {
		if len(w.Examples) < 5 {
			w.Examples = append(w.Examples, s)
		}
	}
	m := a.seen[p]
	for s := lo; s < hi; s++ {
		o := m[uint64(s)]
		switch {
		case o == nil:
			w.Missing++
			example(fmt.Sprintf("seq %d missing", s))
		case o.verdicts > 0 && o.drops > 0:
			w.Both++
			example(fmt.Sprintf("seq %d has both verdicts and a drop", s))
		case o.short != "":
			w.Short++
			example(o.short)
		case o.verdicts > 0:
			w.Evaluated++
			w.Verdicts += o.rules
		default:
			w.Dropped++
		}
		delete(m, uint64(s))
	}
	a.floor[p] = hi
	return w
}
