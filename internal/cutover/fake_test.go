package cutover

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// fakeSource answers instant queries from a table. A key of
// query + "@" + RFC3339 time answers only at that time; a bare query answers
// at any time. A query with no entry returns an empty vector, which is what
// Prometheus returns for a metric nobody exports.
type fakeSource struct {
	mu      sync.Mutex
	instant map[string]float64
	vectors map[string][]Sample
	errs    map[string]error
	ranges  func(q string, start, end time.Time, step time.Duration) []Series
	asked   []string
}

func newFake() *fakeSource {
	return &fakeSource{instant: map[string]float64{}, vectors: map[string][]Sample{}, errs: map[string]error{}}
}

func at(q string, t time.Time) string { return q + "@" + t.UTC().Format(time.RFC3339) }

func (f *fakeSource) Query(_ context.Context, q string, t time.Time) ([]Sample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, q)
	if err, ok := f.errs[q]; ok {
		return nil, err
	}
	for _, k := range []string{at(q, t), q} {
		if v, ok := f.vectors[k]; ok {
			return v, nil
		}
		if v, ok := f.instant[k]; ok {
			return []Sample{{Labels: map[string]string{}, Value: v}}, nil
		}
	}
	return nil, nil
}

func (f *fakeSource) QueryRange(_ context.Context, q string, start, end time.Time, step time.Duration) ([]Series, error) {
	if f.ranges == nil {
		return nil, fmt.Errorf("no range data for %s", q)
	}
	return f.ranges(q, start, end, step), nil
}

// series samples fn every second from start to end.
func series(labels map[string]string, start, end time.Time, fn func(t time.Time) (float64, bool)) Series {
	s := Series{Labels: labels}
	for t := start; !t.After(end); t = t.Add(time.Second) {
		if v, ok := fn(t); ok {
			s.Points = append(s.Points, Point{T: t, V: v})
		}
	}
	return s
}
