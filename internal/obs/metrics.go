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
}

// New registers the metrics on reg.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		EventsIngested: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signalman_events_ingested_total",
			Help: "Records admitted at ingest, each assigned a Seq.",
		}, []string{"source", "partition"}),
	}
	reg.MustRegister(m.EventsIngested)
	return m
}
