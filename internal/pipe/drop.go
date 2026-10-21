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
// Every reason but output-too-large is a decode failure, and that one is a
// property of the event's bytes too. A slow matcher, a full queue, or an
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
	// ReasonRecordTooLarge: key, value, and headers together are over
	// MaxRecordBytes. Outputs carry the raw bytes and more, so a larger
	// record could produce an output no topic accepts. Its drop entry keeps
	// only a prefix of the raw bytes; the full record stays in events.raw.
	ReasonRecordTooLarge = "record-too-large"
	// ReasonOutputTooLarge: the record fit, but one of its outputs
	// (events.norm or an alert) would be over MaxOutputRecordBytes. Fields
	// flatten with their full dotted names, so a small record with many
	// children under a long name can grow without bound. Checked in the
	// sink, before anything for the event is written.
	ReasonOutputTooLarge = "output-too-large"
)

// Size limits. A broker refuses a record over max.message.bytes on every
// retry, so an output that does not fit would wedge its partition, and on
// restart wedge it again. The limits are chosen so that every output fits.
const (
	// MaxOutputRecordBytes is the largest output record the sink writes,
	// leaving room under broker.MaxMessageBytes for batch framing.
	MaxOutputRecordBytes = broker.MaxMessageBytes - 16<<10
	// DefaultMaxRecordBytes caps an admitted record. JSON escapes one byte
	// to at most six, and a drop entry holds the host id (escaped, and again
	// as the key), the source, a cut detail, and the raw bytes in base64, so
	// a drop entry for a record under this size stays under seven times it,
	// which fits MaxOutputRecordBytes.
	DefaultMaxRecordBytes = 128 << 10
	// maxDetail caps a drop's detail, which may quote a field name.
	maxDetail = 1 << 10
	// truncatedRaw and truncatedID cap what a record-too-large entry keeps.
	truncatedRaw = 16 << 10
	truncatedID  = 1 << 10
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
	// RawBytes is the length of the raw record. Truncated is set when Raw,
	// HostID, and Source hold only a prefix, which happens only for
	// record-too-large; the whole record is at Partition and Offset in
	// events.raw while it is retained.
	RawBytes  int  `json:"raw_bytes"`
	Truncated bool `json:"truncated,omitempty"`
}

// DropRecord is the drops topic record for a dropped item, keyed by
// host_id like the record it came from.
// Every drop record fits MaxOutputRecordBytes: see DefaultMaxRecordBytes.
func DropRecord(it *Item) broker.Record {
	e := DropEntry{
		Partition: it.Event.Partition,
		Offset:    it.Rec.Offset,
		Seq:       it.Event.Seq,
		HostID:    it.HostID,
		Source:    it.Event.Source,
		Reason:    it.Drop.Reason,
		Detail:    cut(it.Drop.Detail, maxDetail),
		IngestAt:  it.Event.IngestAt,
		Raw:       it.Event.Raw,
		RawBytes:  len(it.Event.Raw),
	}
	if it.Drop.Reason == ReasonRecordTooLarge {
		e.Truncated = true
		e.HostID = cut(e.HostID, truncatedID)
		e.Source = cut(e.Source, truncatedID)
		e.Raw = e.Raw[:min(len(e.Raw), truncatedRaw)]
	}
	b, err := json.Marshal(e)
	if err != nil {
		// Every field is a plain type; this cannot fail.
		panic(err)
	}
	return broker.Record{Topic: TopicDrops, Partition: broker.AnyPartition, Key: []byte(e.HostID), Value: b}
}

// cut returns at most n bytes of s.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
