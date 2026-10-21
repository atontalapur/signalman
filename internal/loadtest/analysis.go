package loadtest

import (
	"math"
	"sort"
	"time"
)

// Latency summarizes end-to-end latency samples.
type Latency struct {
	N   int           `json:"n"`
	P50 time.Duration `json:"p50_ns"`
	P90 time.Duration `json:"p90_ns"`
	P99 time.Duration `json:"p99_ns"`
	Max time.Duration `json:"max_ns"`
}

// Summarize computes percentiles over the samples recorded in [from, to).
// A zero to means no upper bound. Percentiles are nearest-rank.
func Summarize(ls []LatencySample, from, to time.Duration) Latency {
	var d []time.Duration
	for _, s := range ls {
		if s.At >= from && (to == 0 || s.At < to) {
			d = append(d, s.Lat)
		}
	}
	if len(d) == 0 {
		return Latency{}
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	rank := func(q float64) time.Duration {
		i := int(math.Ceil(q*float64(len(d)))) - 1
		return d[max(0, min(i, len(d)-1))]
	}
	return Latency{N: len(d), P50: rank(0.50), P90: rank(0.90), P99: rank(0.99), Max: d[len(d)-1]}
}

// Saturation is when one stage's queue first filled.
type Saturation struct {
	Stage string `json:"stage"`
	Cap   int    `json:"cap"`
	// First is when depth first reached 90% of Cap; -1 if it never did.
	First    time.Duration `json:"first_ns"`
	MaxDepth float64       `json:"max_depth"`
}

// Saturations reports each stage, ordered by when it filled, never-filled
// stages last. The first entry is the stage that fell behind first in the
// sense that matters for backpressure: a full queue is a stage whose
// consumer cannot keep up with its producer.
func Saturations(ss []Sample, queue, inflight int) []Saturation {
	out := make([]Saturation, numStages)
	for i, name := range StageNames {
		c := queue
		if i == DepthBatches {
			c = inflight
		}
		out[i] = Saturation{Stage: name, Cap: c, First: -1}
		for _, s := range ss {
			d := s.Depth[i]
			out[i].MaxDepth = max(out[i].MaxDepth, d)
			if out[i].First < 0 && d >= 0.9*float64(c) {
				out[i].First = s.At
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].First, out[j].First
		if (a < 0) != (b < 0) {
			return b < 0
		}
		return a < b
	})
	return out
}

// LagPoint is consumer lag at one instant.
type LagPoint struct {
	At  time.Duration `json:"at_ns"`
	Lag int64         `json:"lag"`
}

// LagCurve is produced minus committed, every step, from the samples.
func LagCurve(ss []Sample, step time.Duration) []LagPoint {
	var out []LagPoint
	next := time.Duration(0)
	for _, s := range ss {
		if s.At >= next {
			out = append(out, LagPoint{At: s.At, Lag: s.Produced - s.Committed})
			next = s.At + step
		}
	}
	if n := len(ss); n > 0 && (len(out) == 0 || out[len(out)-1].At != ss[n-1].At) {
		out = append(out, LagPoint{At: ss[n-1].At, Lag: ss[n-1].Produced - ss[n-1].Committed})
	}
	return out
}

// PeakLag is the largest produced-minus-committed in the samples, and when.
func PeakLag(ss []Sample) LagPoint {
	var p LagPoint
	for _, s := range ss {
		if l := s.Produced - s.Committed; l > p.Lag {
			p = LagPoint{At: s.At, Lag: l}
		}
	}
	return p
}

// Throughput is committed records per second between two instants.
func Throughput(ss []Sample, from, to time.Duration) float64 {
	var a, b *Sample
	for i := range ss {
		s := &ss[i]
		if a == nil && s.At >= from {
			a = s
		}
		if s.At <= to {
			b = s
		}
	}
	if a == nil || b == nil || b.At <= a.At {
		return 0
	}
	return float64(b.Committed-a.Committed) / (b.At - a.At).Seconds()
}

// Resources is the process's memory and GC over the samples.
type Resources struct {
	PeakHeapMB float64 `json:"peak_heap_mb"`
	GCs        uint32  `json:"gcs"`
	GCPauseMs  float64 `json:"gc_pause_ms"`
	// PeakTapQ is the deepest tap queue seen at a sample; a queue that
	// filled and emptied between samples does not show here.
	PeakTapQ int `json:"peak_tap_queue"`
	// TapBlocked counts output calls that waited for the tap's checking
	// pool, over the harness's life. It is counted, not sampled: zero
	// means the tap never slowed the pipeline.
	TapBlocked int64 `json:"tap_blocked_sends"`
}

func ResourcesOf(ss []Sample) Resources {
	var r Resources
	if len(ss) == 0 {
		return r
	}
	for _, s := range ss {
		r.PeakHeapMB = max(r.PeakHeapMB, s.HeapMB)
		r.PeakTapQ = max(r.PeakTapQ, s.TapQueue)
	}
	r.GCs = ss[len(ss)-1].NumGC - ss[0].NumGC
	r.GCPauseMs = ss[len(ss)-1].PauseMs - ss[0].PauseMs
	return r
}
