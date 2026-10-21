package obs

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const specPath = "../../docs/spec/signalman-v1.html"

// specMetric is one row of the spec's core metrics table.
type specMetric struct {
	typ    string
	labels []string
}

// coreMetricsTable parses the "Core metrics" table out of the spec, so the
// test fails when either the spec or the code changes without the other.
func coreMetricsTable(t *testing.T) map[string]specMetric {
	t.Helper()
	b, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	start := strings.Index(doc, "<caption>Core metrics</caption>")
	if start < 0 {
		t.Fatal("spec has no Core metrics table")
	}
	end := strings.Index(doc[start:], "</table>")
	if end < 0 {
		t.Fatal("Core metrics table is not closed")
	}
	row := regexp.MustCompile(`<td class="mono-col">(signalman_[a-z_]+)</td><td>([a-z]+) / ([^<]+)</td>`)
	out := map[string]specMetric{}
	for _, m := range row.FindAllStringSubmatch(doc[start:start+end], -1) {
		labelText := m[3]
		if i := strings.Index(labelText, "("); i >= 0 {
			labelText = labelText[:i] // "(exemplars off)" is a note, not a label
		}
		var labels []string
		for l := range strings.SplitSeq(labelText, ",") {
			labels = append(labels, strings.TrimSpace(l))
		}
		slices.Sort(labels)
		out[m[1]] = specMetric{typ: m[2], labels: labels}
	}
	return out
}

// extras are registered metrics that are not in the spec table, each with
// the reason it exists. Anything else registered fails the test.
var extras = map[string]specMetric{
	// The invariant 1 audit's output (Plan C); any increase is a P1.
	"signalman_audit_violations_total": {typ: "counter", labels: []string{"partition"}},
	// How many canary records the generator wrote, so a stalled canary can
	// be told apart from a generator that stopped (Plan E, S-51).
	"signalman_canary_injected_total": {typ: "counter", labels: []string{"partition"}},
}

// touch gives every vector one child, so Gather reports it.
func touch(m *Metrics) {
	m.EventsIngested.WithLabelValues("sysmon", "0").Inc()
	m.EventsDropped.WithLabelValues("parse", "sysmon").Inc()
	m.Verdicts.WithLabelValues("v1", "true").Inc()
	m.RuleMatches.WithLabelValues("r").Inc()
	m.RuleEval.WithLabelValues("r").Observe(1e-6)
	m.StageQueueDepth.WithLabelValues("match").Set(1)
	m.ConsumerLag.WithLabelValues("events.raw", "0").Set(1)
	m.Staleness.Advance(0, time.Unix(0, 0))
	m.CanaryAge.Start(0)
	m.CanaryInjected.WithLabelValues("0").Inc()
	m.RuleSetVersion.WithLabelValues("rs", "tx").Set(1)
	m.AuditViolations.WithLabelValues("0").Inc()
}

func typeName(t dto.MetricType) string {
	switch t {
	case dto.MetricType_COUNTER:
		return "counter"
	case dto.MetricType_GAUGE:
		return "gauge"
	case dto.MetricType_HISTOGRAM:
		return "histogram"
	default:
		return t.String()
	}
}

func TestRegisteredMetricsMatchTheSpecTable(t *testing.T) {
	spec := coreMetricsTable(t)
	if len(spec) != 10 {
		t.Fatalf("spec table has %d metrics, the backlog promises ten: %v", len(spec), spec)
	}
	want := map[string]specMetric{}
	for k, v := range spec {
		want[k] = v
	}
	for k, v := range extras {
		if _, dup := spec[k]; dup {
			t.Fatalf("%s is in the spec table and in extras", k)
		}
		want[k] = v
	}

	reg := prometheus.NewRegistry()
	m := NewWithClock(reg, func() time.Time { return time.Unix(100, 0) })
	touch(m)
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]specMetric{}
	for _, f := range fams {
		var labels []string
		for _, lp := range f.GetMetric()[0].GetLabel() {
			labels = append(labels, lp.GetName())
		}
		slices.Sort(labels)
		got[f.GetName()] = specMetric{typ: typeName(f.GetType()), labels: labels}
	}

	// Every registered collector must have shown up in Gather; otherwise a
	// metric that touch forgot would escape the comparison.
	descs := make(chan *prometheus.Desc, 64)
	go func() {
		for _, c := range m.Collectors() {
			c.Describe(descs)
		}
		close(descs)
	}()
	fq := regexp.MustCompile(`fqName: "([^"]+)"`)
	for d := range descs {
		name := fq.FindStringSubmatch(d.String())[1]
		if _, ok := got[name]; !ok {
			t.Errorf("%s is registered but touch never gave it a series", name)
		}
	}

	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s: in the spec, not registered", name)
			continue
		}
		if g.typ != w.typ || !slices.Equal(g.labels, w.labels) {
			t.Errorf("%s: registered as %s %v, spec says %s %v", name, g.typ, g.labels, w.typ, w.labels)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s: registered but neither in the spec table nor in extras", name)
		}
	}
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name, partition string) (float64, bool) {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "partition" && lp.GetValue() == partition {
					return m.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

// Staleness is now minus the newest event time processed, computed at
// scrape time, so it rises while nothing arrives even with zero lag.
func TestStalenessClimbsBetweenScrapesAndTracksTheNewestEventTime(t *testing.T) {
	now := time.Unix(1000, 0)
	reg := prometheus.NewRegistry()
	m := NewWithClock(reg, func() time.Time { return now })

	if _, ok := gaugeValue(t, reg, "signalman_event_staleness_seconds", "3"); ok {
		t.Fatal("no series before any event on the partition")
	}
	m.Staleness.Advance(3, time.Unix(990, 0))
	m.Staleness.Advance(3, time.Unix(980, 0)) // older: must not move it back
	if v, _ := gaugeValue(t, reg, "signalman_event_staleness_seconds", "3"); v != 10 {
		t.Fatalf("staleness %v, want 10", v)
	}
	now = now.Add(45 * time.Second)
	if v, _ := gaugeValue(t, reg, "signalman_event_staleness_seconds", "3"); v != 55 {
		t.Fatalf("staleness %v after 45s of silence, want 55", v)
	}
	// An event time in the future reads as zero, never negative.
	m.Staleness.Advance(3, now.Add(time.Hour))
	if v, _ := gaugeValue(t, reg, "signalman_event_staleness_seconds", "3"); v != 0 {
		t.Fatalf("staleness %v for a future event time, want 0", v)
	}
}

func TestCanaryAgeStartsOnceAndResets(t *testing.T) {
	now := time.Unix(1000, 0)
	reg := prometheus.NewRegistry()
	m := NewWithClock(reg, func() time.Time { return now })

	m.CanaryAge.Start(1)
	now = now.Add(20 * time.Second)
	m.CanaryAge.Start(1) // already tracked: does not reset
	if v, _ := gaugeValue(t, reg, "signalman_canary_age_seconds", "1"); v != 20 {
		t.Fatalf("age %v, want 20", v)
	}
	m.CanaryAge.Reset(1)
	if v, _ := gaugeValue(t, reg, "signalman_canary_age_seconds", "1"); v != 0 {
		t.Fatalf("age %v after reset, want 0", v)
	}
	now = now.Add(7 * time.Second)
	if v, _ := gaugeValue(t, reg, "signalman_canary_age_seconds", "1"); v != 7 {
		t.Fatalf("age %v, want 7", v)
	}
}
