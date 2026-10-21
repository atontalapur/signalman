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

// SourceUnknown is the metric label for a record with no source header.
const SourceUnknown = "unknown"

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
