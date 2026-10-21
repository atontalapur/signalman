// Package chsink is the ClickHouse alert sink: it consumes the alerts topic
// and inserts each record into the alerts table from the spec (DDL in
// deploy/clickhouse/), committing offsets only after the insert succeeds.
//
// Delivery is at-least-once, the same choice the pipeline makes. A crash
// between the insert and the commit redelivers the batch, and the copies
// collapse in the table's ReplacingMergeTree, keyed on (partition, seq,
// rule_id). When ClickHouse is down the sink retries the batch it holds and
// stops polling, so the outage shows up as consumer lag on alerts, bounded
// by retention, and nothing is dropped.
//
// A record the table cannot hold (undecodable, a non-UUID rule_id, an
// unknown severity, a time outside DateTime64) would fail its batch on
// every retry and stop the sink for every partition. It goes to
// alerts.dead instead, with its position and the reason, and its offset is
// committed only after that write is durable.
package chsink

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/pipe"
)

// Inserter writes rows to the alerts table. Insert returns nil only once
// every row is stored. On error any subset may have been stored, so the
// caller retries the whole slice, which the table absorbs. An error that
// wraps ErrPermanent will not succeed on retry, and the caller stops.
type Inserter interface {
	Insert(ctx context.Context, rows []pipe.Alert) error
}

// Config sizes the sink. Sizes are stated by the operator; New rejects a
// zero.
type Config struct {
	// Group is the alerts consumer group.
	Group string
	// BatchRows flushes the buffer once it holds this many rows. The buffer
	// never holds more than BatchRows plus one poll.
	BatchRows int
	// FlushInterval flushes a non-empty buffer this long after its first
	// row arrived, so a quiet topic still reaches the table.
	FlushInterval time.Duration
	// RetryBackoff is the first wait after a failed insert; waits double up
	// to MaxBackoff. Defaults 100ms and 5s.
	RetryBackoff time.Duration
	MaxBackoff   time.Duration
}

func (c Config) validate() error {
	var errs []error
	if c.Group == "" {
		errs = append(errs, errors.New("group is required"))
	}
	if c.BatchRows <= 0 {
		errs = append(errs, fmt.Errorf("BatchRows must be set and positive, got %d", c.BatchRows))
	}
	if c.FlushInterval <= 0 {
		errs = append(errs, fmt.Errorf("FlushInterval must be set and positive, got %s", c.FlushInterval))
	}
	return errors.Join(errs...)
}

// Sink moves alerts from the topic to the table.
type Sink struct {
	cfg Config
	b   broker.Broker
	ins Inserter
	m   *obs.Metrics
	log *slog.Logger

	// Lag accounting, touched only by the Run goroutine.
	hw        map[broker.TopicPartition]int64
	committed map[broker.TopicPartition]int64
}

// New builds a sink. m and log may be nil.
func New(cfg Config, b broker.Broker, ins Inserter, m *obs.Metrics, log *slog.Logger) (*Sink, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("sink config: %w", err)
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = 100 * time.Millisecond
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 5 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Sink{cfg: cfg, b: b, ins: ins, m: m, log: log}, nil
}

// Run consumes alerts until ctx ends or a record cannot be inserted. Rows
// not committed when it returns are redelivered to the next Run.
//
// The loop is single-threaded on purpose: while an insert is being retried
// nothing polls, which is the backpressure. Kafka holds what has not been
// read, so the only buffer is the one batch in hand.
func (s *Sink) Run(ctx context.Context) error {
	cons, err := s.b.Consume(s.cfg.Group, []string{pipe.TopicAlerts})
	if err != nil {
		return err
	}
	defer cons.Close()
	if err := s.loadCommitted(ctx); err != nil {
		return err
	}
	if parts, err := s.b.EndOffsets(ctx, pipe.TopicAlertsDead); err != nil || len(parts) == 0 {
		return fmt.Errorf("dead-letter topic %s is required and was not found: %v", pipe.TopicAlertsDead, err)
	}
	if err := s.startCanary(ctx); err != nil {
		return err
	}

	var (
		buf      []pipe.Alert
		first    = map[broker.TopicPartition]int64{}
		next     = map[broker.TopicPartition]int64{}
		deadline time.Time
	)
	// flush inserts buf and commits next. next also covers dead-lettered
	// records, which are durable already, so a batch of only those skips
	// the insert.
	flush := func() error {
		if len(buf) > 0 {
			if err := s.insert(ctx, buf); err != nil {
				if errors.Is(err, ErrPermanent) {
					return fmt.Errorf("insert of %d rows (%s) cannot succeed; nothing from this batch was committed: %w",
						len(buf), span(first, next), err)
				}
				return err
			}
			s.canary(buf)
		}
		s.commit(ctx, cons, next)
		buf, first, next = nil, map[broker.TopicPartition]int64{}, map[broker.TopicPartition]int64{}
		return nil
	}
	for {
		pctx, cancel := ctx, context.CancelFunc(func() {})
		if len(next) > 0 {
			pctx, cancel = context.WithDeadline(ctx, deadline)
		}
		f, err := cons.Poll(pctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if len(next) > 0 && errors.Is(err, context.DeadlineExceeded) {
				if err := flush(); err != nil {
					return err
				}
				continue
			}
			s.log.Warn("poll failed, retrying", "err", err)
			if !sleep(ctx, s.cfg.RetryBackoff) {
				return ctx.Err()
			}
			continue
		}
		s.observe(f.HighWatermarks)
		if len(next) == 0 && len(f.Records) > 0 {
			deadline = time.Now().Add(s.cfg.FlushInterval)
		}
		for _, r := range f.Records {
			a, err := Decode(r)
			if err != nil {
				if err := s.deadLetter(ctx, r, err); err != nil {
					return err
				}
			} else {
				buf = append(buf, a)
			}
			tp := broker.TopicPartition{Topic: r.Topic, Partition: r.Partition}
			if _, ok := first[tp]; !ok {
				first[tp] = r.Offset
			}
			next[tp] = max(next[tp], r.Offset+1)
		}
		if len(buf) >= s.cfg.BatchRows || (len(next) > 0 && !time.Now().Before(deadline)) {
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

// insert retries until the rows are stored or ctx ends. An unreachable
// ClickHouse is lag, so this never gives up on its own. A permanent error
// is returned at once: it would fail the same way forever.
func (s *Sink) insert(ctx context.Context, rows []pipe.Alert) error {
	wait := s.cfg.RetryBackoff
	for {
		err := s.ins.Insert(ctx, rows)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrPermanent) {
			return err
		}
		s.log.Warn("insert failed, retrying the batch; not polling until it lands", "rows", len(rows), "err", err)
		if !sleep(ctx, wait) {
			return ctx.Err()
		}
		wait = min(2*wait, s.cfg.MaxBackoff)
	}
}

// startCanary tracks signalman_sink_canary_age_seconds for every events.raw
// partition from now. A partition whose canary alert never reaches the
// table climbs from the moment the sink started, which is what makes a
// ClickHouse that died before the first canary visible. The partitions are
// listed once: one gauge per partition, and a partition added later is
// tracked from the next restart.
func (s *Sink) startCanary(ctx context.Context) error {
	if s.m == nil {
		return nil
	}
	parts, err := s.b.EndOffsets(ctx, pipe.TopicEventsRaw)
	if err != nil || len(parts) == 0 {
		return fmt.Errorf("topic %s is required for the canary age and was not found: %v", pipe.TopicEventsRaw, err)
	}
	for p := range parts {
		s.m.SinkCanaryAge.Start(p)
	}
	return nil
}

// canary resets the canary age of every partition with a canary alert in
// rows, which are stored. A partition not tracked at startup is skipped, so
// the gauge never grows past the partitions events.raw had.
func (s *Sink) canary(rows []pipe.Alert) {
	if s.m == nil {
		return
	}
	for _, a := range rows {
		if a.RuleID != pipe.CanaryRuleID {
			continue
		}
		if _, ok := s.m.SinkCanaryAge.Age(a.Partition); ok {
			s.m.SinkCanaryAge.Reset(a.Partition)
		}
	}
}

// Headers on an alerts.dead record. The key and value are the original
// record's.
const (
	HeaderDeadTopic     = "signalman-dead-topic"
	HeaderDeadPartition = "signalman-dead-partition"
	HeaderDeadOffset    = "signalman-dead-offset"
	HeaderDeadReason    = "signalman-dead-reason"
	// HeaderDeadTruncated is set, to the original value length, when the
	// value was cut to fit broker.MaxMessageBytes.
	HeaderDeadTruncated = "signalman-dead-truncated"
	maxDeadReason       = 1024
)

// deadRecord is the alerts.dead record for r, refused for reason. It fits
// broker.MaxMessageBytes: the reason is capped and the value cut if needed.
func deadRecord(r broker.Record, reason error) broker.Record {
	msg := reason.Error()
	if len(msg) > maxDeadReason {
		msg = msg[:maxDeadReason]
	}
	d := broker.Record{
		Topic:     pipe.TopicAlertsDead,
		Partition: broker.AnyPartition,
		Key:       r.Key,
		Headers: []broker.Header{
			{Key: HeaderDeadTopic, Value: []byte(r.Topic)},
			{Key: HeaderDeadPartition, Value: []byte(strconv.Itoa(int(r.Partition)))},
			{Key: HeaderDeadOffset, Value: []byte(strconv.FormatInt(r.Offset, 10))},
			{Key: HeaderDeadReason, Value: []byte(msg)},
		},
	}
	// Room for the truncation header too, so adding it cannot overflow.
	room := broker.MaxMessageBytes - broker.RecordSize(d) - len(HeaderDeadTruncated) - 20
	d.Value = r.Value
	if len(r.Value) > room {
		d.Value = r.Value[:max(0, room)]
		d.Headers = append(d.Headers, broker.Header{Key: HeaderDeadTruncated, Value: []byte(strconv.Itoa(len(r.Value)))})
	}
	return d
}

// deadLetter writes r to alerts.dead, retrying a transient failure until it
// is durable or ctx ends. A permanent failure stops the sink with r's
// position, nothing committed.
func (s *Sink) deadLetter(ctx context.Context, r broker.Record, reason error) error {
	d := deadRecord(r, reason)
	wait := s.cfg.RetryBackoff
	for {
		err := s.b.Produce(ctx, []broker.Record{d})
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, broker.ErrPermanent) {
			return fmt.Errorf("%s/%d offset %d: %v; the dead-letter write to %s cannot succeed and nothing from this batch was committed: %w",
				r.Topic, r.Partition, r.Offset, reason, pipe.TopicAlertsDead, err)
		}
		s.log.Warn("dead-letter write failed, retrying; not polling until it lands", "err", err)
		if !sleep(ctx, wait) {
			return ctx.Err()
		}
		wait = min(2*wait, s.cfg.MaxBackoff)
	}
	s.log.Error("alert record the table cannot hold; written to "+pipe.TopicAlertsDead,
		"topic", r.Topic, "partition", r.Partition, "offset", r.Offset, "reason", reason)
	if s.m != nil {
		s.m.SinkDeadLetters.Inc()
	}
	return nil
}

// commit records the next offset per partition. A failed commit is logged,
// not retried: the rows are stored, the next commit supersedes it, and the
// worst case is a redelivery the table collapses.
func (s *Sink) commit(ctx context.Context, cons broker.Consumer, next map[broker.TopicPartition]int64) {
	if err := cons.Commit(ctx, next); err != nil {
		s.log.Warn("offset commit failed; the batch will be redelivered", "err", err)
		return
	}
	for tp, off := range next {
		s.committed[tp] = off
		s.setLag(tp)
	}
}

func (s *Sink) loadCommitted(ctx context.Context) error {
	c, err := s.b.CommittedOffsets(ctx, s.cfg.Group, pipe.TopicAlerts)
	if err != nil {
		return err
	}
	s.hw = map[broker.TopicPartition]int64{}
	s.committed = map[broker.TopicPartition]int64{}
	for p, off := range c {
		s.committed[broker.TopicPartition{Topic: pipe.TopicAlerts, Partition: p}] = off
	}
	return nil
}

func (s *Sink) observe(hw map[broker.TopicPartition]int64) {
	for tp, off := range hw {
		s.hw[tp] = off
		s.setLag(tp)
	}
}

// setLag is signalman_consumer_lag_records for the sink's group: the log end
// minus the committed offset. During an outage it is where the
// backpressure surfaces.
func (s *Sink) setLag(tp broker.TopicPartition) {
	hw, ok := s.hw[tp]
	if !ok || s.m == nil {
		return
	}
	s.m.ConsumerLag.WithLabelValues(tp.Topic, strconv.Itoa(int(tp.Partition))).Set(float64(max(0, hw-s.committed[tp])))
}

// span names the offsets a batch holds, per partition in order, such as
// "alerts/0 offsets 4-9, alerts/2 offsets 0-3".
func span(first, next map[broker.TopicPartition]int64) string {
	tps := slices.SortedFunc(maps.Keys(first), func(a, b broker.TopicPartition) int {
		return cmp.Or(cmp.Compare(a.Topic, b.Topic), cmp.Compare(a.Partition, b.Partition))
	})
	parts := make([]string, len(tps))
	for i, tp := range tps {
		parts[i] = fmt.Sprintf("%s/%d offsets %d-%d", tp.Topic, tp.Partition, first[tp], next[tp]-1)
	}
	return strings.Join(parts, ", ")
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
