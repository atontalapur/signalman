// Package pipe is the signalmand pipeline: ingest, normalize, match, and the
// sink that makes a batch durable before its offsets are committed.
//
// Every event admitted at ingest leaves the pipeline as exactly one verdict
// per enabled rule or exactly one drop ledger entry. Nothing in this package
// may discard an event any other way, and nothing may buffer without a
// bound: every stage boundary is a bounded channel, and a full channel stops
// the consumer polling rather than shedding work.
package pipe

import (
	"slices"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/event"
)

// Topic names, from the spec's topic table (phase 04).
const (
	TopicEventsRaw  = "events.raw"
	TopicEventsNorm = "events.norm"
	TopicAlerts     = "alerts"
	TopicVerdictsV1 = "verdicts.v1"
	TopicVerdictsV2 = "verdicts.v2"
	TopicDrops      = "drops"
)

// TopicAlertsDead is where signalman-sink writes an alerts record the
// ClickHouse table cannot hold, with its position and the reason. Not in the
// spec's topic table; see docs/pipeline.md.
const TopicAlertsDead = "alerts.dead"

// HeaderSource is the events.raw record header naming the source ("sysmon",
// "auditd", "cloudtrail"). The record key is the host_id and the value is
// the untouched source record.
const HeaderSource = "source"

// Sources is the closed set of source header values the pipeline accepts,
// from the spec's Event.Source. A record naming any other source is a drop
// with ReasonUnknownSource.
var Sources = []string{"auditd", "cloudtrail", "sysmon"}

// Source metric labels for a record outside Sources. The header is
// producer-controlled bytes: used as a label, a value that is not UTF-8
// panics client_golang, and any value at all grows a new series.
const (
	// SourceUnknown is the label for a record with no source header.
	SourceUnknown = "unknown"
	// SourceOther is the label for a header that is not in Sources,
	// including one that is not valid UTF-8.
	SourceOther = "other"
)

// knownSource reports whether src is one of Sources.
func knownSource(src string) bool {
	return slices.Contains(Sources, src)
}

// sourceLabel is the metric label for a source header: the header itself
// when it is in Sources, otherwise SourceUnknown or SourceOther. Every label
// derived from a record goes through here.
func sourceLabel(src string) string {
	switch {
	case src == "":
		return SourceUnknown
	case knownSource(src):
		return src
	default:
		return SourceOther
	}
}

// Item is one record's trip through the pipeline. Ingest creates it with the
// event's identity; normalize fills in the fields or a drop; match fills in
// the verdicts. Exactly one of Drop and Verdicts is set when it reaches the
// sink.
//
// When the batch has a shadow engine, match also fills Shadow with its
// verdicts, or leaves Shadow nil and sets ShadowFailure when the shadow
// panicked or broke the verdict contract on this event.
type Item struct {
	Rec           broker.Record
	HostID        string
	Event         *event.Event
	Drop          *Drop
	Verdicts      []event.Verdict
	Shadow        []event.Verdict
	ShadowFailure string
}
