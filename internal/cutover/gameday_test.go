package cutover

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/pipe"
)

var t0 = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC) // a Tuesday

// ruleIDs returns n rule ids, and at least one in each of the buckets
// asked for, so a test can put a rule inside or outside a rollout.
func ruleIDs(n int, buckets ...int) []string {
	var out []string
	need := map[int]bool{}
	for _, b := range buckets {
		need[b] = true
	}
	for i := 0; len(out) < n || len(need) > 0; i++ {
		id := fmt.Sprintf("rule-%d", i)
		b := pipe.RolloutBucket(id)
		if need[b] {
			delete(need, b)
			out = append(out, id)
		} else if len(out) < n {
			out = append(out, id)
		}
	}
	return out
}

// sim is a signalmand under a constant one-event-per-second load on every
// rule, as Prometheus would see it. A rollout change written at w reaches
// the gauge at w+applyAfter, and batches formed before w+servedAfter keep
// the old routing.
type sim struct {
	file        string
	rules       []string
	applyAfter  time.Duration
	servedAfter time.Duration
	neverApply  bool
	last        int
	changes     []simChange
}

type simChange struct {
	at       time.Time
	from, to int
}

func (s *sim) read(t *testing.T) int {
	b, err := os.ReadFile(s.file)
	if err != nil {
		t.Fatal(err)
	}
	n, err := pipe.ParseRollout(b)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// percent is the rollout at t, with the change landing after delay.
func (s *sim) percent(t time.Time, delay time.Duration) int {
	p := s.last
	if len(s.changes) > 0 {
		p = s.changes[0].from
	}
	for _, c := range s.changes {
		if s.neverApply {
			break
		}
		if !t.Before(c.at.Add(delay)) {
			p = c.to
		}
	}
	return p
}

func (s *sim) source(t *testing.T) *fakeSource {
	f := newFake()
	f.ranges = func(q string, start, end time.Time, step time.Duration) []Series {
		// Measure starts its window Lead (2m) before the write.
		if cur := s.read(t); cur != s.last {
			s.changes = append(s.changes, simChange{at: start.Add(2 * time.Minute), from: s.last, to: cur})
			s.last = cur
		}
		switch q {
		case qRolloutMax, qRolloutMin:
			return []Series{series(nil, start, end, func(x time.Time) (float64, bool) {
				return float64(s.percent(x, s.applyAfter)), true
			})}
		case qAlertsByKey:
			var out []Series
			for _, id := range s.rules {
				for _, eng := range []string{engineV1, engineV2} {
					served := func(x time.Time) bool {
						return (eng == engineV2) == pipe.ServedByShadow(id, s.percent(x, s.servedAfter))
					}
					var n float64
					exists := served(start)
					if exists {
						n = 1000
					}
					out = append(out, series(map[string]string{"engine": eng, "rule_id": id}, start, end, func(x time.Time) (float64, bool) {
						if served(x) {
							n++
							exists = true
						}
						return n, exists
					}))
				}
			}
			return out
		}
		t.Fatalf("unexpected range query %s", q)
		return nil
	}
	return f
}

// clock is a fake clock that Sleep advances.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }
func (c *clock) Sleep(_ context.Context, d time.Duration) error {
	c.now = c.now.Add(d)
	return nil
}

func rolloutFile(t *testing.T, percent int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rollout")
	if err := os.WriteFile(p, fmt.Appendf(nil, "%d\n", percent), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func drillConfig(t *testing.T, s *sim, c *clock) DrillConfig {
	src := s.source(t)
	// Preflight reads the gauge as signalmand would export it now.
	src.instant[qRolloutMin], src.instant[qRolloutMax] = float64(s.last), float64(s.last)
	return DrillConfig{RolloutFile: s.file, From: 100, To: 0, Source: src, Now: c.Now, Sleep: func(ctx context.Context, d time.Duration) error {
		_ = c.Sleep(ctx, d)
		// Between changes the gauge settles at the file's value.
		v := float64(s.read(t))
		src.instant[qRolloutMin], src.instant[qRolloutMax] = v, v
		return nil
	}}
}

func TestDrillMeasuresRollbackAndRollForward(t *testing.T) {
	s := &sim{file: rolloutFile(t, 100), rules: ruleIDs(20), applyAfter: 6 * time.Second, servedAfter: 8 * time.Second, last: 100}
	c := &clock{now: t0}
	d, err := RunDrill(context.Background(), drillConfig(t, s, c))
	if err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]*Step{"rollback": d.Rollback, "roll-forward": d.RollForward} {
		if !st.Measured() {
			t.Fatalf("%s not measured: %s", name, st.Problem)
		}
		// The last old-routing alert is at w+7s, after the gauge at w+6s.
		if got := *st.Seconds; got != 7 {
			t.Errorf("%s took %gs, want 7: %s", name, got, st)
		}
		if st.MovedRules != 20 {
			t.Errorf("%s: %d moved rules alerting, want all 20", name, st.MovedRules)
		}
	}
	if d.Rollback.From != 100 || d.Rollback.To != 0 || d.RollForward.From != 0 || d.RollForward.To != 100 {
		t.Fatalf("steps %+v %+v", d.Rollback, d.RollForward)
	}
	if d.Rollback.OldEngine != "v2" || d.RollForward.OldEngine != "v1" {
		t.Fatalf("old engines %s %s", d.Rollback.OldEngine, d.RollForward.OldEngine)
	}
	if got := d.RollForward.WrittenAt.Sub(d.Rollback.WrittenAt); got != 5*time.Minute {
		t.Fatalf("roll-forward %s after the rollback, want the 5m hold", got)
	}
	if n := s.read(t); n != 100 {
		t.Fatalf("the drill ends at %d%%, want back at 100%%", n)
	}
}

func TestDrillStopsAtTheRollbackTargetWhenNotMeasured(t *testing.T) {
	s := &sim{file: rolloutFile(t, 100), rules: ruleIDs(5), applyAfter: 6 * time.Second, servedAfter: 8 * time.Second, last: 100, neverApply: true}
	c := &clock{now: t0}
	d, err := RunDrill(context.Background(), drillConfig(t, s, c))
	if err == nil || !strings.Contains(err.Error(), "left at 0%") {
		t.Fatalf("err = %v", err)
	}
	if d.RollForward != nil || d.Rollback == nil || d.Rollback.Measured() {
		t.Fatalf("drill %+v", d)
	}
	if !strings.Contains(d.Rollback.Problem, "never read 0%") {
		t.Fatalf("problem %q", d.Rollback.Problem)
	}
	if n := s.read(t); n != 0 {
		t.Fatalf("rollout %d%%, want left at the rollback target", n)
	}
}

func TestDrillRollbackOnly(t *testing.T) {
	s := &sim{file: rolloutFile(t, 100), rules: ruleIDs(5), applyAfter: 2 * time.Second, servedAfter: 3 * time.Second, last: 100}
	c := &clock{now: t0}
	cfg := drillConfig(t, s, c)
	cfg.NoForward = true
	d, err := RunDrill(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Rollback.Measured() || d.RollForward != nil || s.read(t) != 0 {
		t.Fatalf("drill %+v, file %d", d, s.read(t))
	}
}

func TestDrillRefusesAMismatchedStart(t *testing.T) {
	s := &sim{file: rolloutFile(t, 50), rules: ruleIDs(5), last: 50}
	c := &clock{now: t0}
	if _, err := RunDrill(context.Background(), drillConfig(t, s, c)); err == nil || !strings.Contains(err.Error(), "holds 50%") {
		t.Fatalf("err = %v", err)
	}
	if n := s.read(t); n != 50 {
		t.Fatalf("the refused drill wrote %d%%", n)
	}

	// The file is right but signalmand has not applied it yet.
	s = &sim{file: rolloutFile(t, 100), rules: ruleIDs(5), last: 100}
	cfg := drillConfig(t, s, c)
	cfg.Source.(*fakeSource).instant[qRolloutMin] = 50
	if _, err := RunDrill(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "has not applied") {
		t.Fatalf("err = %v", err)
	}
}

// At a partial rollback only the rules between the two percentages move;
// a rule outside them says nothing about the change.
func TestMeasureCountsOnlyMovedRules(t *testing.T) {
	ids := ruleIDs(0, 0, 70)
	s := &sim{file: rolloutFile(t, 0), rules: ids, applyAfter: 3 * time.Second, servedAfter: 4 * time.Second,
		last: 1, changes: nil}
	src := s.source(t)
	w := t0
	st, err := Measure(context.Background(), src, MeasureConfig{From: 1, To: 0, WrittenAt: w, Until: w.Add(90 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Measured() || *st.Seconds != 3 || st.MovedRules != 1 {
		t.Fatalf("step %s, moved %d", st.String(), st.MovedRules)
	}
}

func TestMeasureReportsAnOldEngineStillServing(t *testing.T) {
	s := &sim{file: rolloutFile(t, 0), rules: ruleIDs(5), applyAfter: 3 * time.Second, servedAfter: 80 * time.Second, last: 100}
	st, err := Measure(context.Background(), s.source(t), MeasureConfig{From: 100, To: 0, WrittenAt: t0, Until: t0.Add(90 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if st.Measured() || !strings.Contains(st.Problem, "may still be serving") {
		t.Fatalf("step %s", st.String())
	}
}

func TestMeasureWithoutNewAlertsIsNotMeasured(t *testing.T) {
	src := newFake()
	src.ranges = func(q string, start, end time.Time, _ time.Duration) []Series {
		if q == qAlertsByKey {
			return nil
		}
		return []Series{series(nil, start, end, func(x time.Time) (float64, bool) {
			if x.After(t0.Add(2 * time.Second)) {
				return 0, true
			}
			return 100, true
		})}
	}
	st, err := Measure(context.Background(), src, MeasureConfig{From: 100, To: 0, WrittenAt: t0, Until: t0.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if st.Measured() || !strings.Contains(st.Problem, "handover is not shown") {
		t.Fatalf("step %s", st.String())
	}
}

func TestRisesCountsResetsAndNewSeries(t *testing.T) {
	start := t0
	ps := []Point{{start.Add(5 * time.Second), 3}, {start.Add(6 * time.Second), 3}, {start.Add(7 * time.Second), 1}, {start.Add(8 * time.Second), 2}}
	got := rises(ps, start, time.Second)
	want := []time.Time{start.Add(5 * time.Second), start.Add(7 * time.Second), start.Add(8 * time.Second)}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("rises %v, want %v", got, want)
	}
	if got := rises([]Point{{start, 3}, {start.Add(time.Second), 3}}, start, time.Second); len(got) != 0 {
		t.Fatalf("a series present from the start has no rise at its first sample: %v", got)
	}
}

func TestWriteRolloutReplacesTheFile(t *testing.T) {
	p := rolloutFile(t, 100)
	if err := WriteRollout(p, 0, t0); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := pipe.ParseRollout(b); err != nil || n != 0 {
		t.Fatalf("rollout file %q: %d, %v", b, n, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("the temporary file was left behind: %v", ents)
	}
}
