package pipe

import (
	"strconv"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/obs"
)

// Ingest admits records from events.raw and assigns each its Seq.
//
// Seq is the record's offset in its events.raw partition. The alternative,
// a counter persisted beside the consumer offset, was rejected:
//
//   - The offset is already per-partition, monotonic, and durable in the
//     broker, so it survives a restart with nothing extra to store or to get
//     wrong.
//   - Delivery is at-least-once. A redelivered record must get the Seq it got
//     the first time, because the alert sink deduplicates on (partition, seq,
//     rule_id) and the verdict digest folds the seq. A counter would hand a
//     redelivered record a fresh Seq, which turns every redelivery into a
//     duplicate alert and a digest divergence.
//   - Any consumer, including a replay or the shadow lane, derives the same
//     Seq from the same record without coordination.
//
// The cost is that Seq is monotonic, not dense: a compacted or transactional
// events.raw would leave gaps. The digest folds the seq values themselves
// and tolerates gaps; the invariant audit assumes events.raw is a plain,
// non-transactional topic, which is how deploy/docker-compose.yml creates it.
type Ingest struct {
	m *obs.Metrics
}

func NewIngest(m *obs.Metrics) *Ingest { return &Ingest{m: m} }

// Admit turns a record into an item. It never fails: whatever the record
// holds, it is now admitted, and leaves as verdicts or as a drop.
func (in *Ingest) Admit(r broker.Record) *Item {
	src := string(r.Header(HeaderSource))
	in.m.EventsIngested.WithLabelValues(sourceLabel(src), strconv.Itoa(int(r.Partition))).Inc()
	return &Item{
		Rec:    r,
		HostID: string(r.Key),
		Event: &event.Event{
			Seq:       uint64(r.Offset),
			Partition: r.Partition,
			Source:    src,
			// The record timestamp, not the wall clock, so a replay of the
			// same record reproduces the same event. Nothing evaluates it.
			IngestAt: r.Timestamp,
			Raw:      r.Value,
		},
	}
}
