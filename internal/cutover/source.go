// Package cutover checks the gate ladder in docs/cutover.md (spec phase 09)
// and runs the rollback game day. Each gate's criteria are checked from the
// sources the spec names: Prometheus for the live gates, a corpus replay and
// the fuzzer's counters for G0, a game day result for the rollback
// measurements, and docs/cutover.md itself for retirement. A gate passes only
// when every one of its checks does; a check that cannot be made from those
// sources is reported as unchecked until an operator attests it.
package cutover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Sample is one series of an instant query result.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Point is one sample of a range query result.
type Point struct {
	T time.Time
	V float64
}

// Series is one series of a range query result, in time order.
type Series struct {
	Labels map[string]string
	Points []Point
}

// Source answers PromQL. The gate checker and the game day read every
// metric through it, so tests substitute a fake.
type Source interface {
	// Query evaluates q at one instant. A scalar result is one sample with
	// no labels; an empty vector is an empty slice.
	Query(ctx context.Context, q string, at time.Time) ([]Sample, error)
	// QueryRange evaluates q at every step from start to end.
	QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]Series, error)
}

// Prom is a Source over the Prometheus HTTP API.
type Prom struct {
	// Base is the server URL, such as http://localhost:9090.
	Base   string
	Client *http.Client
}

var _ Source = (*Prom)(nil)

// Query calls /api/v1/query.
func (p *Prom) Query(ctx context.Context, q string, at time.Time) ([]Sample, error) {
	v := url.Values{"query": {q}, "time": {promTime(at)}}
	var res promResult
	if err := p.get(ctx, "/api/v1/query", v, &res); err != nil {
		return nil, err
	}
	switch res.ResultType {
	case "scalar":
		var pt [2]json.RawMessage
		if err := json.Unmarshal(res.Result, &pt); err != nil {
			return nil, err
		}
		_, val, err := decodePoint(pt)
		if err != nil {
			return nil, err
		}
		return []Sample{{Labels: map[string]string{}, Value: val}}, nil
	case "vector":
		var vec []struct {
			Metric map[string]string  `json:"metric"`
			Value  [2]json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(res.Result, &vec); err != nil {
			return nil, err
		}
		out := make([]Sample, 0, len(vec))
		for _, s := range vec {
			_, val, err := decodePoint(s.Value)
			if err != nil {
				return nil, err
			}
			out = append(out, Sample{Labels: s.Metric, Value: val})
		}
		return out, nil
	}
	return nil, fmt.Errorf("query %q returned a %s, want a vector or scalar", q, res.ResultType)
}

// QueryRange calls /api/v1/query_range.
func (p *Prom) QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]Series, error) {
	v := url.Values{"query": {q}, "start": {promTime(start)}, "end": {promTime(end)},
		"step": {strconv.FormatFloat(step.Seconds(), 'f', -1, 64)}}
	var res promResult
	if err := p.get(ctx, "/api/v1/query_range", v, &res); err != nil {
		return nil, err
	}
	if res.ResultType != "matrix" {
		return nil, fmt.Errorf("range query %q returned a %s, want a matrix", q, res.ResultType)
	}
	var mat []struct {
		Metric map[string]string    `json:"metric"`
		Values [][2]json.RawMessage `json:"values"`
	}
	if err := json.Unmarshal(res.Result, &mat); err != nil {
		return nil, err
	}
	out := make([]Series, 0, len(mat))
	for _, s := range mat {
		sr := Series{Labels: s.Metric, Points: make([]Point, 0, len(s.Values))}
		for _, raw := range s.Values {
			t, val, err := decodePoint(raw)
			if err != nil {
				return nil, err
			}
			sr.Points = append(sr.Points, Point{T: t, V: val})
		}
		out = append(out, sr)
	}
	return out, nil
}

type promResult struct {
	ResultType string          `json:"resultType"`
	Result     json.RawMessage `json:"result"`
}

func (p *Prom) get(ctx context.Context, path string, v url.Values, into *promResult) error {
	c := p.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.Base, "/")+path+"?"+v.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	var env struct {
		Status    string     `json:"status"`
		Data      promResult `json:"data"`
		ErrorType string     `json:"errorType"`
		Error     string     `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("prometheus %s: HTTP %d, body is not the API envelope: %w", path, resp.StatusCode, err)
	}
	if env.Status != "success" {
		return fmt.Errorf("prometheus %s %q: %s: %s", path, v.Get("query"), env.ErrorType, env.Error)
	}
	*into = env.Data
	return nil
}

// decodePoint reads the API's [unix seconds, "value"] pair.
func decodePoint(pt [2]json.RawMessage) (time.Time, float64, error) {
	var ts float64
	if err := json.Unmarshal(pt[0], &ts); err != nil {
		return time.Time{}, 0, fmt.Errorf("sample time %s: %w", pt[0], err)
	}
	var s string
	if err := json.Unmarshal(pt[1], &s); err != nil {
		return time.Time{}, 0, fmt.Errorf("sample value %s: %w", pt[1], err)
	}
	val, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("sample value %q: %w", s, err)
	}
	sec := int64(ts)
	return time.Unix(sec, int64((ts-float64(sec))*1e9)).UTC().Round(time.Millisecond), val, nil
}

func promTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', 3, 64)
}

// promDur writes d the way PromQL range selectors take it.
func promDur(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return fmt.Sprintf("%ds", (d+time.Second-1)/time.Second)
	}
}
