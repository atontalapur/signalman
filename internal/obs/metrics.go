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
	}
	reg.MustRegister(m.EventsIngested, m.EventsDropped, m.StageQueueDepth, m.ConsumerLag)
	return m
}
