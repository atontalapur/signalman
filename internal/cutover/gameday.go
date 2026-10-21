package cutover

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/atontalapur/signalman/internal/pipe"
)

// Engine names as the alert metric labels them.
const (
	engineV1 = "v1"
	engineV2 = "v2"
)

// Step is one rollout change and when it took effect, measured from
// metrics. Every time is the timestamp of the first range-query sample that
// showed it, so each is an upper bound on when it happened, by at most the
// scrape interval: the measured duration is never shorter than the real one.
type Step struct {
	From int `json:"from_percent"`
	To   int `json:"to_percent"`
	// WrittenAt is when the rollout file was renamed into place.
	WrittenAt     time.Time `json:"written_at"`
	ObservedUntil time.Time `json:"observed_until"`
	// OldEngine served the moved rules before the change, NewEngine after.
	// The moved rules are those with RolloutBucket between From and To.
	OldEngine  string `json:"old_engine"`
	NewEngine  string `json:"new_engine"`
	MovedRules int    `json:"moved_rules_alerting"`
	// AppliedAt is the first sample of signalman_rollout_percent at To on
	// every instance.
	AppliedAt *time.Time `json:"applied_at,omitempty"`
	// LastOldAlertAt is the last sample at which signalman_alerts_total for
	// a moved rule rose under OldEngine: batches formed before the change
	// finishing under the old routing.
	LastOldAlertAt *time.Time `json:"last_old_alert_at,omitempty"`
	// FirstNewAlertAt is the first sample at which a moved rule's alerts
	// rose under NewEngine.
	FirstNewAlertAt *time.Time `json:"first_new_alert_at,omitempty"`
	// TookEffectAt is the later of AppliedAt and LastOldAlertAt: from then
	// on the new engine alone serves the moved rules.
	TookEffectAt *time.Time `json:"took_effect_at,omitempty"`
	// Seconds is TookEffectAt minus WrittenAt. Nil when not measured.
	Seconds *float64 `json:"seconds,omitempty"`
	// Problem says why the step is not measured.
	Problem           string  `json:"problem,omitempty"`
	ResolutionSeconds float64 `json:"resolution_seconds"`
}

// Measured reports whether the step took effect and was timed.
func (s *Step) Measured() bool { return s != nil && s.Seconds != nil }

// Duration is the measured time to take effect.
func (s *Step) Duration() time.Duration {
	if !s.Measured() {
		return 0
	}
	return time.Duration(*s.Seconds * float64(time.Second))
}

func (s *Step) String() string {
	if s == nil {
		return "not run"
	}
	if !s.Measured() {
		return fmt.Sprintf("%d%% to %d%% written %s: not measured: %s", s.From, s.To, s.WrittenAt.Format(time.RFC3339), s.Problem)
	}
	return fmt.Sprintf("%d%% to %d%% written %s, took effect %s: %.1fs (%s serving %d alerting moved rules from %s; resolution %.0fs)",
		s.From, s.To, s.WrittenAt.Format(time.RFC3339), s.TookEffectAt.Format(time.RFC3339), *s.Seconds,
		s.NewEngine, s.MovedRules, s.FirstNewAlertAt.Format(time.RFC3339), s.ResolutionSeconds)
}

// Drill is one game day: a rollback and, after a hold, the roll-forward.
type Drill struct {
	RolloutFile string    `json:"rollout_file"`
	StartedAt   time.Time `json:"started_at"`
	Rollback    *Step     `json:"rollback,omitempty"`
	RollForward *Step     `json:"roll_forward,omitempty"`
}

// MeasureConfig is one rollout change to time.
type MeasureConfig struct {
	From, To  int
	WrittenAt time.Time
	// Until is the end of the observation window.
	Until time.Time
	// Step is the range query resolution. Default 1s; samples change only
	// at scrapes, so the resolution that matters is the scrape interval.
	Step time.Duration
	// Quiet is how long the old engine must have served no moved rule
	// before Until for the change to count as complete. Default 20s, more
	// than one 15s scrape.
	Quiet time.Duration
	// Lead is how far before WrittenAt the window starts, to see each
	// counter's value before the change. Default 2m.
	Lead time.Duration
}

func (c *MeasureConfig) defaults() {
	if c.Step <= 0 {
		c.Step = time.Second
	}
	if c.Quiet <= 0 {
		c.Quiet = 20 * time.Second
	}
	if c.Lead <= 0 {
		c.Lead = 2 * time.Minute
	}
}

// Queries the measurement makes.
const (
	qRolloutMax  = `max(signalman_rollout_percent)`
	qRolloutMin  = `min(signalman_rollout_percent)`
	qAlertsByKey = `sum by (engine, rule_id) (signalman_alerts_total)`
)

// Measure times one rollout change from signalman_rollout_percent and
// signalman_alerts_total. An error is a failed query; a change that did not
// take effect in the window is a Step with a Problem.
func Measure(ctx context.Context, src Source, c MeasureConfig) (Step, error) {
	c.defaults()
	s := Step{From: c.From, To: c.To, WrittenAt: c.WrittenAt, ObservedUntil: c.Until,
		OldEngine: engineV1, NewEngine: engineV2, ResolutionSeconds: c.Step.Seconds()}
	if c.To < c.From {
		s.OldEngine, s.NewEngine = engineV2, engineV1
	}
	if c.To == c.From {
		s.Problem = "from and to are the same percentage; nothing moves"
		return s, nil
	}
	start := c.WrittenAt.Add(-c.Lead)

	// The change is applied everywhere when the slowest instance reads To:
	// the highest gauge going down, the lowest going up.
	gq := qRolloutMin
	if c.To < c.From {
		gq = qRolloutMax
	}
	gs, err := src.QueryRange(ctx, gq, start, c.Until, c.Step)
	if err != nil {
		return s, err
	}
	for _, sr := range gs {
		for _, p := range sr.Points {
			if p.T.After(c.WrittenAt) && p.V == float64(c.To) {
				t := p.T
				s.AppliedAt = &t
				break
			}
		}
	}

	as, err := src.QueryRange(ctx, qAlertsByKey, start, c.Until, c.Step)
	if err != nil {
		return s, err
	}
	lo, hi := min(c.From, c.To), max(c.From, c.To)
	moved := map[string]bool{}
	var oldUps, newUps []time.Time
	for _, sr := range as {
		id, eng := sr.Labels["rule_id"], sr.Labels["engine"]
		if b := pipe.RolloutBucket(id); b < lo || b >= hi {
			continue
		}
		ups := rises(sr.Points, start, c.Step)
		switch eng {
		case s.OldEngine:
			oldUps = append(oldUps, after(ups, c.WrittenAt)...)
		case s.NewEngine:
			nu := after(ups, c.WrittenAt)
			if len(nu) > 0 {
				moved[id] = true
			}
			newUps = append(newUps, nu...)
		}
	}
	sortTimes(oldUps)
	sortTimes(newUps)
	s.MovedRules = len(moved)

	if s.AppliedAt == nil {
		s.Problem = fmt.Sprintf("signalman_rollout_percent never read %d%% on every instance between %s and %s",
			c.To, c.WrittenAt.Format(time.RFC3339), c.Until.Format(time.RFC3339))
		return s, nil
	}
	if len(oldUps) > 0 {
		t := oldUps[len(oldUps)-1]
		s.LastOldAlertAt = &t
	}
	if len(newUps) == 0 {
		s.Problem = fmt.Sprintf("no alert for a moved rule (bucket %d to %d) was served by %s in the window, so the handover is not shown; run the drill under traffic that matches moved rules",
			lo, hi-1, s.NewEngine)
		return s, nil
	}
	t := newUps[0]
	s.FirstNewAlertAt = &t
	eff := *s.AppliedAt
	if s.LastOldAlertAt != nil && s.LastOldAlertAt.After(eff) {
		eff = *s.LastOldAlertAt
	}
	if c.Until.Sub(eff) < c.Quiet {
		s.Problem = fmt.Sprintf("%s still served a moved rule at %s, less than %s before the window ended; it may still be serving",
			s.OldEngine, eff.Format(time.RFC3339), c.Quiet)
		return s, nil
	}
	s.TookEffectAt = &eff
	sec := eff.Sub(c.WrittenAt).Seconds()
	s.Seconds = &sec
	return s, nil
}

// rises is the times a counter series went up: a higher value than the
// sample before, or a reset (a restarted process counts from zero again). A
// series whose first sample is after the window start was created inside
// the window, and its first nonzero value is a rise from nothing.
func rises(ps []Point, start time.Time, step time.Duration) []time.Time {
	var out []time.Time
	for i, p := range ps {
		if i == 0 {
			if p.T.After(start.Add(step)) && p.V > 0 {
				out = append(out, p.T)
			}
			continue
		}
		if prev := ps[i-1].V; p.V > prev || (p.V < prev && p.V > 0) {
			out = append(out, p.T)
		}
	}
	return out
}

func after(ts []time.Time, t time.Time) []time.Time {
	var out []time.Time
	for _, x := range ts {
		if x.After(t) {
			out = append(out, x)
		}
	}
	return out
}

func sortTimes(ts []time.Time) { sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) }) }

// DrillConfig is a game day: roll back from From to To, hold, roll forward.
type DrillConfig struct {
	// RolloutFile is signalmand's -rollout file.
	RolloutFile string
	// From is the rollout the drill starts and ends at, To the rollback
	// target. G5 is 100 to 0.
	From, To int
	// Observe is how long each change is watched before it is measured.
	// It must exceed the 30 s budget plus a scrape. Default 90s.
	Observe time.Duration
	// Hold is how long the rollback stays in place, counted from the
	// rollback, before rolling forward. Default 5m.
	Hold time.Duration
	// NoForward stops after the rollback: a rollback drill for G2 to G4.
	NoForward bool
	Measure   MeasureConfig // Step, Quiet, Lead; the rest is filled in
	Source    Source
	Now       func() time.Time
	// Sleep waits d or until ctx ends.
	Sleep func(ctx context.Context, d time.Duration) error
	Log   func(format string, args ...any)
}

// RunDrill runs a game day against a live signalmand. It checks the
// rollout file and the gauge both read From, writes To with a rename,
// measures the rollback, holds, writes From back, and measures that.
//
// If the rollback is not measured, the drill stops with the rollout at To,
// which is v1 serving the moved rules: the side to be on when something did
// not behave as expected. The returned Drill holds what was measured either
// way.
func RunDrill(ctx context.Context, c DrillConfig) (Drill, error) {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = sleep
	}
	if c.Log == nil {
		c.Log = func(string, ...any) {}
	}
	if c.Observe <= 0 {
		c.Observe = 90 * time.Second
	}
	if c.Hold <= 0 {
		c.Hold = 5 * time.Minute
	}
	d := Drill{RolloutFile: c.RolloutFile, StartedAt: c.Now().UTC()}
	if c.From == c.To || c.From < 0 || c.From > 100 || c.To < 0 || c.To > 100 {
		return d, fmt.Errorf("drill from %d%% to %d%%: want two different percentages from 0 to 100", c.From, c.To)
	}
	if c.Hold < c.Observe {
		return d, fmt.Errorf("hold %s is shorter than observe %s", c.Hold, c.Observe)
	}
	if err := preflight(ctx, c, c.From); err != nil {
		return d, err
	}

	c.Log("rolling back: writing %d%% to %s", c.To, c.RolloutFile)
	rb, err := change(ctx, c, c.From, c.To)
	d.Rollback = &rb
	if err != nil {
		return d, err
	}
	c.Log("rollback: %s", rb.String())
	if !rb.Measured() {
		return d, fmt.Errorf("rollback was not measured (%s); the rollout is left at %d%%", rb.Problem, c.To)
	}
	if c.NoForward {
		return d, nil
	}
	if err := c.Sleep(ctx, c.Hold-c.Observe); err != nil {
		return d, err
	}
	if err := preflight(ctx, c, c.To); err != nil {
		return d, fmt.Errorf("before rolling forward: %w", err)
	}
	c.Log("rolling forward: writing %d%% to %s", c.From, c.RolloutFile)
	rf, err := change(ctx, c, c.To, c.From)
	d.RollForward = &rf
	if err != nil {
		return d, err
	}
	c.Log("roll-forward: %s", rf.String())
	if !rf.Measured() {
		return d, fmt.Errorf("roll-forward was not measured: %s", rf.Problem)
	}
	return d, nil
}

// preflight checks the file and every instance's gauge read want, so the
// drill measures the change it makes and not one already in flight.
func preflight(ctx context.Context, c DrillConfig, want int) error {
	b, err := os.ReadFile(c.RolloutFile)
	if err != nil {
		return err
	}
	n, err := pipe.ParseRollout(b)
	if err != nil {
		return fmt.Errorf("%s: %w", c.RolloutFile, err)
	}
	if n != want {
		return fmt.Errorf("%s holds %d%%, the drill expects %d%%", c.RolloutFile, n, want)
	}
	now := c.Now()
	for _, q := range []string{qRolloutMin, qRolloutMax} {
		v, ok, err := scalar(ctx, c.Source, q, now)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%s has no data: is signalmand scraped?", q)
		}
		if v != float64(want) {
			return fmt.Errorf("%s is %g, the drill expects %d: an earlier change has not applied", q, v, want)
		}
	}
	return nil
}

func change(ctx context.Context, c DrillConfig, from, to int) (Step, error) {
	if err := WriteRollout(c.RolloutFile, to, c.Now()); err != nil {
		return Step{From: from, To: to}, err
	}
	written := c.Now().UTC()
	if err := c.Sleep(ctx, c.Observe); err != nil {
		return Step{From: from, To: to, WrittenAt: written}, err
	}
	m := c.Measure
	m.From, m.To, m.WrittenAt, m.Until = from, to, written, c.Now().UTC()
	return Measure(ctx, c.Source, m)
}

// WriteRollout replaces the rollout file with percent by writing a sibling
// and renaming it over the file, so signalmand's poller never reads half a
// file.
func WriteRollout(path string, percent int, now time.Time) error {
	dir, base := filepath.Split(path)
	tmp, err := os.CreateTemp(dir, "."+base+".*")
	if err != nil {
		return err
	}
	body := fmt.Sprintf("# written by cutover gameday at %s\n%d\n", now.UTC().Format(time.RFC3339), percent)
	if _, err := tmp.WriteString(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// scalar sums an instant query's samples. ok is false for an empty result.
func scalar(ctx context.Context, src Source, q string, at time.Time) (float64, bool, error) {
	ss, err := src.Query(ctx, q, at)
	if err != nil {
		return 0, false, err
	}
	if len(ss) == 0 {
		return 0, false, nil
	}
	var sum float64
	for _, s := range ss {
		sum += s.Value
	}
	return sum, true, nil
}
