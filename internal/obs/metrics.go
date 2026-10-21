// Package obs holds the pipeline's metrics. The names and labels come from
// the spec's core metrics table (phase 06) and are fixed: the load document,
// the cutover gates, and the alert rules all refer to them.
package obs

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

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
	// RuleEval is the time one rule's condition walk takes on one event,
	// sampled. Labels: rule_id. Exemplars are off: nothing observes with
	// one, and a trace per rule per event is cardinality nobody reads.
	RuleEval *prometheus.HistogramVec
	// Staleness is now minus the newest event time processed per
	// partition. It is not lag: lag counts records not yet consumed, and
	// staleness catches an upstream that stopped producing, which leaves
	// lag at zero. Labels: partition.
	Staleness *AgeGauge
	// CanaryAge is the time since the last canary alert reached the sink
	// on each partition. Labels: partition.
	CanaryAge *AgeGauge
	// CanaryInjected counts canary records the generator wrote, so a
	// stalled canary can be told apart from a generator that stopped. Not
	// in the spec's table. Labels: partition.
	CanaryInjected *prometheus.CounterVec
	// RuleSetVersion is 1 for the rule set the next batch will use.
	// Labels: ruleset_v, taxonomy_v.
	RuleSetVersion *prometheus.GaugeVec
	// AuditViolations counts admitted events the invariant 1 audit could
	// not account for: missing, both verdicts and a drop, or verdicts short
	// of the rule count. Not in the spec's table; it is the audit's output,
	// and any increase is a P1. Labels: partition.
	AuditViolations *prometheus.CounterVec
}

// RuleEvalBuckets spans 100ns to about 26ms by factors of four. A rule walk
// is microseconds; the top buckets exist for the regex that should have
// been a contains.
var RuleEvalBuckets = prometheus.ExponentialBuckets(1e-7, 4, 10)

// New registers the metrics on reg, with the wall clock for the age gauges.
func New(reg prometheus.Registerer) *Metrics { return NewWithClock(reg, time.Now) }

// NewWithClock registers the metrics on reg. now is read only by the age
// gauges, at scrape time.
func NewWithClock(reg prometheus.Registerer, now func() time.Time) *Metrics {
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
		RuleEval: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "signalman_rule_eval_seconds",
			Help:    "Seconds one rule's condition walk takes on one event, sampled.",
			Buckets: RuleEvalBuckets,
		}, []string{"rule_id"}),
		Staleness: newAgeGauge("signalman_event_staleness_seconds",
			"Seconds between now and the newest event time processed on the partition.", now),
		CanaryAge: newAgeGauge("signalman_canary_age_seconds",
			"Seconds since the last canary alert on the partition reached the sink.", now),
		CanaryInjected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_canary_injected_total",
			Help: "Canary records written to events.raw, per partition.",
		}, []string{"partition"}),
		RuleSetVersion: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "signalman_ruleset_version_info",
			Help: "1 for the rule set and taxonomy versions new batches are evaluated under.",
		}, []string{"ruleset_v", "taxonomy_v"}),
		AuditViolations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_audit_violations_total",
			Help: "Committed events with no verdicts and no drop, with both, or with too few verdicts.",
		}, []string{"partition"}),
	}
	reg.MustRegister(m.Collectors()...)
	return m
}

// Collectors is every collector New registers.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.EventsIngested, m.EventsDropped, m.StageQueueDepth, m.ConsumerLag,
		m.Verdicts, m.RuleMatches, m.RuleEval, m.Staleness, m.CanaryAge, m.CanaryInjected, m.RuleSetVersion, m.AuditViolations}
}
