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
	TopicDrops      = "drops"
)

// HeaderSource is the events.raw record header naming the source ("sysmon",
// "auditd", "cloudtrail"). The record key is the host_id and the value is
// the untouched source record.
const HeaderSource = "source"

// SourceUnknown is the metric label for a record with no source header.
const SourceUnknown = "unknown"

// Item is one record's trip through the pipeline. Ingest creates it with the
// event's identity.
type Item struct {
	Rec    broker.Record
	HostID string
	Event  *event.Event
}
