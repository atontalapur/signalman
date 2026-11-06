// Package obs holds the pipeline's metrics. The names and labels come from
// the spec's core metrics table (phase 06) and are fixed: the load document,
// the cutover gates, and the alert rules all refer to them.
package obs

import "github.com/prometheus/client_golang/prometheus"

// Metrics is every metric the pipeline exports. Build one per registry; the
// tests use a fresh registry each so counts do not leak between them.
type Metrics struct {
	// EventsIngested counts records admitted at ingest.
	// Labels: source, partition.
	EventsIngested *prometheus.CounterVec
	// EventsDropped counts drop ledger entries. Labels: reason, source.
	EventsDropped *prometheus.CounterVec
	// StageQueueDepth is the occupancy of each bounded stage channel.
	// Labels: stage.
	StageQueueDepth *prometheus.GaugeVec
	// ConsumerLag is records in the log not yet committed by the group.
	// Labels: topic, partition.
	ConsumerLag *prometheus.GaugeVec
	// Verdicts counts durable verdicts. Labels: engine, matched.
	Verdicts *prometheus.CounterVec
	// RuleMatches counts durable matches per rule. Labels: rule_id.
	RuleMatches *prometheus.CounterVec
	// RuleSetVersion is 1 for the rule set the next batch will use.
	// Labels: ruleset_v, taxonomy_v.
	RuleSetVersion *prometheus.GaugeVec
	// AuditViolations counts admitted events the invariant 1 audit could
	// not account for: missing, both verdicts and a drop, or verdicts short
	// of the rule count. Not in the spec's table; it is the audit's output,
	// and any increase is a P1. Labels: partition.
	AuditViolations *prometheus.CounterVec
	// SinkDeadLetters counts alerts records signalman-sink wrote to
	// alerts.dead instead of the table. Not in the spec's table; any
	// increase is an alert stored nowhere queryable.
	SinkDeadLetters prometheus.Counter
}

// New registers the metrics on reg.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		EventsIngested: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_events_ingested_total",
			Help: "Records admitted at ingest, each assigned a Seq.",
		}, []string{"source", "partition"}),
		EventsDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_events_dropped_total",
			Help: "Admitted records written to the drop ledger instead of producing verdicts.",
		}, []string{"reason", "source"}),
		StageQueueDepth: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "signalman_stage_queue_depth",
			Help: "Items waiting in each bounded stage channel.",
		}, []string{"stage"}),
		ConsumerLag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "signalman_consumer_lag_records",
			Help: "Log end offset minus the committed offset, per partition.",
		}, []string{"topic", "partition"}),
		Verdicts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_verdicts_total",
			Help: "Verdicts written durably, one per event per enabled rule.",
		}, []string{"engine", "matched"}),
		RuleMatches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_rule_matches_total",
			Help: "Matched verdicts written durably, per rule.",
		}, []string{"rule_id"}),
		RuleSetVersion: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "signalman_ruleset_version_info",
			Help: "1 for the rule set and taxonomy versions new batches are evaluated under.",
		}, []string{"ruleset_v", "taxonomy_v"}),
		AuditViolations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_audit_violations_total",
			Help: "Committed events with no verdicts and no drop, with both, or with too few verdicts.",
		}, []string{"partition"}),
		SinkDeadLetters: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "signalman_sink_dead_letters_total",
			Help: "Alerts records written to alerts.dead because the alerts table cannot hold them.",
		}),
	}
	reg.MustRegister(m.EventsIngested, m.EventsDropped, m.StageQueueDepth, m.ConsumerLag,
		m.Verdicts, m.RuleMatches, m.RuleSetVersion, m.AuditViolations, m.SinkDeadLetters)
	return m
}
