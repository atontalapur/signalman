package pipe

import (
	"encoding/json"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
)

// Drop reason codes. The set is closed: a drop is the only way an admitted
// event may leave the pipeline without verdicts, so every way it can happen
// has a name here and a label value on signalman_events_dropped_total.
//
// Every reason is a decode failure. A slow matcher, a full queue, or an
// unavailable sink is never a reason to drop: those produce lag.
const (
	// ReasonParse: not JSON, not a JSON object, or trailing data after it.
	ReasonParse = "parse"
	// ReasonInvalidUTF8: the record is not valid UTF-8. Decoding it would
	// replace bad bytes with U+FFFD, and case folding would then make two
	// different byte strings compare equal.
	ReasonInvalidUTF8 = "invalid-utf8"
	// ReasonValueTooLong: a string value is longer than MaxValueLen. The
	// wildcard matcher costs O(value x pattern), so an unbounded value is an
	// unbounded evaluation.
	ReasonValueTooLong = "value-too-long"
	// ReasonNestedValue: a list inside a list, an object inside a list, or
	// objects nested deeper than MaxDepth. Value has no nested list kind, and
	// a value no rule can ever match must not pass as a quiet non-match.
	ReasonNestedValue = "nested-value"
	// ReasonDuplicateField: a key appears twice, either literally or after
	// mapping onto the taxonomy's spelling. Picking one would make the event
	// depend on key order.
	ReasonDuplicateField = "duplicate-field"
	// ReasonMissingSource: the record has no source header.
	ReasonMissingSource = "missing-source"
	// ReasonEventTime: the event time field is absent or unparseable. Event
	// time comes from the record, never the wall clock, so there is nothing
	// to fall back on.
	ReasonEventTime = "event-time"
	// ReasonPanic: the normalizer panicked on this record. The record is
	// dropped and the partition moves on.
	ReasonPanic = "panic"
)

// Drop is why an item left as a ledger entry instead of verdicts.
type Drop struct {
	Reason string
	Detail string
}

// DropEntry is the drops topic record body: the event's identity, why it
// was dropped, and the raw bytes exactly as they arrived.
type DropEntry struct {
	Partition int32     `json:"partition"`
	Offset    int64     `json:"offset"`
	Seq       uint64    `json:"seq"`
	HostID    string    `json:"host_id"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason"`
	Detail    string    `json:"detail"`
	IngestAt  time.Time `json:"ingest_at"`
	// Raw is base64 in JSON, so bytes that are not UTF-8 survive intact.
	Raw []byte `json:"raw"`
}

// DropRecord is the drops topic record for a dropped item, keyed by
// host_id like the record it came from.
func DropRecord(it *Item) broker.Record {
	b, err := json.Marshal(DropEntry{
		Partition: it.Event.Partition,
		Offset:    it.Rec.Offset,
		Seq:       it.Event.Seq,
		HostID:    it.HostID,
		Source:    it.Event.Source,
		Reason:    it.Drop.Reason,
		Detail:    it.Drop.Detail,
		IngestAt:  it.Event.IngestAt,
		Raw:       it.Event.Raw,
	})
	if err != nil {
		// Every field is a plain type; this cannot fail.
		panic(err)
	}
	return broker.Record{Topic: TopicDrops, Partition: broker.AnyPartition, Key: []byte(it.HostID), Value: b}
}
