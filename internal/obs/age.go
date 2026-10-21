package obs

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AgeGauge is a per-partition gauge whose value is the seconds since a
// recorded instant. The value is computed when the gauge is scraped, not
// when it is set, so it keeps climbing while nothing updates it. That is the
// whole point of both users: event staleness and canary age are only
// interesting when the pipeline has stopped touching them.
//
// The clock is read here and nowhere near an engine. Wall-clock time is
// allowed in metrics and forbidden in verdicts.
type AgeGauge struct {
	desc *prometheus.Desc
	now  func() time.Time

	mu sync.Mutex
	at map[int32]time.Time // partitions are bounded by the topic's count
}

func newAgeGauge(name, help string, now func() time.Time) *AgeGauge {
	return &AgeGauge{
		desc: prometheus.NewDesc(name, help, []string{"partition"}, nil),
		now:  now,
		at:   map[int32]time.Time{},
	}
}

// Advance moves the partition's instant forward to t. An earlier t is
// ignored, so out-of-order event times never make staleness jump back.
func (g *AgeGauge) Advance(p int32, t time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if cur, ok := g.at[p]; !ok || t.After(cur) {
		g.at[p] = t
	}
}

// Reset sets the partition's instant to now: its age reads zero.
func (g *AgeGauge) Reset(p int32) { g.Advance(p, g.now()) }

// Start begins tracking a partition from now if it is not tracked yet. A
// partition that is started and never reset climbs from the moment it was
// started, which is what makes a consumer that never came up visible.
func (g *AgeGauge) Start(p int32) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.at[p]; !ok {
		g.at[p] = now
	}
}

// Age is the partition's current value, and whether it is tracked.
func (g *AgeGauge) Age(p int32) (time.Duration, bool) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.at[p]
	if !ok {
		return 0, false
	}
	return max(0, now.Sub(t)), true
}

func (g *AgeGauge) Describe(ch chan<- *prometheus.Desc) { ch <- g.desc }

func (g *AgeGauge) Collect(ch chan<- prometheus.Metric) {
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for p, t := range g.at {
		ch <- prometheus.MustNewConstMetric(g.desc, prometheus.GaugeValue,
			max(0, now.Sub(t)).Seconds(), strconv.Itoa(int(p)))
	}
}
