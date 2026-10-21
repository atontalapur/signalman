package cutover

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/atontalapur/signalman/internal/corpus"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

// Status is one check's outcome.
type Status string

const (
	// Pass: the criterion was checked and holds.
	Pass Status = "pass"
	// Fail: the criterion was checked and does not hold.
	Fail Status = "fail"
	// Unchecked: the evidence was missing or could not be read. The gate
	// cannot pass.
	Unchecked Status = "unchecked"
	// Attested: no source here can check the criterion, and an operator
	// stated the evidence. It counts as met, and the statement is recorded.
	Attested Status = "attested"
)

// Check is one criterion of one gate.
type Check struct {
	Key       string `json:"key"`
	Criterion string `json:"criterion"`
	Status    Status `json:"status"`
	Evidence  string `json:"evidence"`
	// Manual checks have no machine source and can only be attested.
	Manual bool `json:"manual,omitempty"`
}

// Report is one gate evaluated at one time.
type Report struct {
	Gate string `json:"gate"`
	// Step is the G3 percentage, 10 or 50; zero for every other gate.
	Step   int           `json:"step,omitempty"`
	At     time.Time     `json:"at"`
	Window time.Duration `json:"window"`
	Checks []Check       `json:"checks"`
}

// Passed reports whether every check passed or was attested.
func (r Report) Passed() bool {
	if len(r.Checks) == 0 {
		return false
	}
	for _, c := range r.Checks {
		if c.Status != Pass && c.Status != Attested {
			return false
		}
	}
	return true
}

// Name is the gate as the ladder names it: "G2", or "G3 10%".
func (r Report) Name() string {
	if r.Step != 0 {
		return fmt.Sprintf("%s %d%%", r.Gate, r.Step)
	}
	return r.Gate
}

// Gates is the ladder in order.
var Gates = []string{"G0", "G1", "G2", "G3", "G4", "G5", "G6"}

// Config is what a gate is checked against. Only the fields the gate uses
// are read.
type Config struct {
	Gate string
	// Percent is the G3 step: 10 or 50.
	Percent int
	// At is the end of the window the gate is checked over. Zero is now;
	// a time after now is refused.
	At time.Time
	// Now is the clock At is checked against. Default time.Now.
	Now func() time.Time
	// Window overrides the gate's hold: 7d for G1, 48h for G2 to G4, 14d
	// for G6.
	Window time.Duration
	Source Source
	// Attest maps a manual check's key to the operator's evidence for it.
	Attest map[string]string

	// G0: corpus replay, fuzzer counters, property tests.
	Rules, Taxonomy, Corpus string
	Partitions              int // default 8
	FuzzStats               string
	FuzzMin                 int64 // default 1e8
	// RunTests runs the property and equivalence tests. Nil leaves the
	// check unchecked.
	RunTests func(ctx context.Context) (string, error)

	// Drill is a game day result: the rollback G2 to G4 need, and the
	// rollback and roll-forward G5 and G6 need.
	Drill     *Drill
	DrillFile string

	// NoiseSigma is how many standard deviations a rule's alert count may
	// move between windows. Default 3.
	NoiseSigma float64
	// VerdictTolerance bounds |v2/v1 - 1| on verdict counts. increase()
	// extrapolates at the window edges, so the two counts are not exactly
	// equal even when every event has both. Default 0.001.
	VerdictTolerance float64
	// RollbackBudget is the most a rollback or roll-forward may take.
	// Default 30s.
	RollbackBudget time.Duration
	// DrillSlack is how far outside the hold a G2 to G4 rollback may have
	// been written and still count for it: before the hold starts, or
	// after it ends and before the check. Default 24h.
	DrillSlack time.Duration
	// ScrapeInterval is Prometheus's scrape interval, which sets how many
	// samples a fully covered window holds. Default 15s, as
	// deploy/prometheus/prometheus.yml has it.
	ScrapeInterval time.Duration
	// MinCoverage is the share of a window's expected samples that must
	// exist for the window to count as observed. Default 0.95.
	MinCoverage float64
	// BaselineAt ends a window in which v1 served every rule, for G6's
	// alert volume comparison. Zero leaves it unchecked.
	BaselineAt time.Time
	// Doc is docs/cutover.md, which G6 reads for the dates of G0 to G5 and
	// the divergence log.
	Doc string
	// Location and the business hours [BusinessStart, BusinessEnd) on
	// weekdays are when G5's game day must start. Default UTC, 9 to 17.
	Location                   *time.Location
	BusinessStart, BusinessEnd int
	// FullTraffic is the share of the trailing 7 day mean ingest rate the
	// game day must start under to count as full traffic. Default 0.8.
	FullTraffic float64
}

func (c *Config) defaults() {
	if c.Partitions <= 0 {
		c.Partitions = 8
	}
	if c.FuzzMin <= 0 {
		c.FuzzMin = 100_000_000
	}
	if c.NoiseSigma <= 0 {
		c.NoiseSigma = 3
	}
	if c.VerdictTolerance <= 0 {
		c.VerdictTolerance = 0.001
	}
	if c.RollbackBudget <= 0 {
		c.RollbackBudget = 30 * time.Second
	}
	if c.DrillSlack <= 0 {
		c.DrillSlack = 24 * time.Hour
	}
	if c.ScrapeInterval <= 0 {
		c.ScrapeInterval = 15 * time.Second
	}
	if c.MinCoverage <= 0 {
		c.MinCoverage = 0.95
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Location == nil {
		c.Location = time.UTC
	}
	if c.BusinessStart == 0 && c.BusinessEnd == 0 {
		c.BusinessStart, c.BusinessEnd = 9, 17
	}
	if c.FullTraffic <= 0 {
		c.FullTraffic = 0.8
	}
	if c.Window <= 0 {
		switch c.Gate {
		case "G1":
			c.Window = 7 * 24 * time.Hour
		case "G2", "G3", "G4":
			c.Window = 48 * time.Hour
		case "G6":
			c.Window = 14 * 24 * time.Hour
		}
	}
}

// Evaluate checks one gate. An error means the gate could not be checked
// at all (unknown gate, bad step, a window that ends after now); a failed
// query is an unchecked check.
func Evaluate(ctx context.Context, c Config) (Report, error) {
	c.defaults()
	now := c.Now()
	if c.At.IsZero() {
		c.At = now
	}
	r := Report{Gate: c.Gate, At: c.At.UTC(), Window: c.Window}
	if c.At.After(now) {
		return r, fmt.Errorf("-at %s is after now (%s): a window that has not ended cannot be checked",
			c.At.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if c.Gate != "G3" && c.Percent != 0 {
		return r, fmt.Errorf("-percent is for G3 only")
	}
	if c.Gate != "G0" && c.Source == nil {
		return r, fmt.Errorf("%s needs a metric source", c.Gate)
	}
	e := &evaluator{c: c, ctx: ctx}
	switch c.Gate {
	case "G0":
		e.g0()
	case "G1":
		e.g1()
	case "G2":
		e.step(1, false)
	case "G3":
		if c.Percent != 10 && c.Percent != 50 {
			return r, fmt.Errorf("G3 has two steps, 10 and 50; got -percent %d", c.Percent)
		}
		r.Step = c.Percent
		e.step(c.Percent, false)
	case "G4":
		e.step(100, true)
	case "G5":
		e.g5()
	case "G6":
		e.g6()
	default:
		return r, fmt.Errorf("unknown gate %q; the ladder is %s", c.Gate, strings.Join(Gates, ", "))
	}
	for i := range e.checks {
		ch := &e.checks[i]
		if ch.Manual && ch.Status == Unchecked {
			if ev, ok := c.Attest[ch.Key]; ok && strings.TrimSpace(ev) != "" {
				ch.Status, ch.Evidence = Attested, "attested: "+ev
			}
		}
	}
	for k := range c.Attest {
		if !e.has(k) {
			return r, fmt.Errorf("-attest %s: %s has no check with that key", k, c.Gate)
		}
	}
	r.Checks = e.checks
	return r, nil
}

type evaluator struct {
	c      Config
	ctx    context.Context
	checks []Check
}

func (e *evaluator) has(key string) bool {
	for _, c := range e.checks {
		if c.Key == key {
			return true
		}
	}
	return false
}

func (e *evaluator) add(key, criterion string, st Status, evidence string, args ...any) {
	e.checks = append(e.checks, Check{Key: key, Criterion: criterion, Status: st, Evidence: fmt.Sprintf(evidence, args...)})
}

func (e *evaluator) manual(key, criterion, how string) {
	e.checks = append(e.checks, Check{Key: key, Criterion: criterion, Status: Unchecked, Manual: true,
		Evidence: "no metric or file here checks this; " + how + " (attest with -attest " + key + "=<evidence>)"})
}

func (e *evaluator) w() string { return promDur(e.c.Window) }

// q runs an instant query at the gate's time and sums it. A failed query
// adds an unchecked check and returns ok false.
func (e *evaluator) q(key, criterion, query string, at time.Time) (v float64, present, ok bool) {
	v, present, err := scalar(e.ctx, e.c.Source, query, at)
	if err != nil {
		e.add(key, criterion, Unchecked, "query %s: %v", query, err)
		return 0, false, false
	}
	return v, present, true
}

// zero checks a counter did not increase over the window. metric must be
// exported at zero before it can count: increase() never counts a series'
// first sample, so a series made by its first count reads as no increase,
// and no series is no evidence.
func (e *evaluator) zero(key, criterion, metric string) {
	query := fmt.Sprintf("sum(increase(%s[%s]))", metric, e.w())
	v, present, ok := e.q(key, criterion, query, e.c.At)
	if !ok {
		return
	}
	switch {
	case !present:
		e.add(key, criterion, Unchecked, "%s has no series: is its exporter scraped? (`%s`)", metric, query)
	case v == 0:
		e.add(key, criterion, Pass, "0 over %s (`%s`)", e.w(), query)
	default:
		e.add(key, criterion, Fail, "%g over %s (`%s`)", v, e.w(), query)
	}
}

// coverage checks every instance exporting metric was scraped for at least
// MinCoverage of the window ending at at. Sums, minimums and maximums over
// a window see only the samples that exist, so without this a gate held for
// a day of a seven-day window would pass on that day alone. metric must be
// a series each instance exports from start-up.
func (e *evaluator) coverage(key, what, metric string, at time.Time) {
	crit := fmt.Sprintf("%s scraped for at least %g%% of the %s ending %s", what, 100*e.c.MinCoverage, e.w(), at.UTC().Format(time.RFC3339))
	query := fmt.Sprintf("min(count_over_time(%s[%s]))", metric, e.w())
	v, present, ok := e.q(key, crit, query, at)
	if !ok {
		return
	}
	want := float64(e.c.Window / e.c.ScrapeInterval)
	if !present {
		e.add(key, crit, Unchecked, "%s has no samples in the window: is it scraped? (`%s`)", metric, query)
		return
	}
	st := Fail
	if v >= e.c.MinCoverage*want {
		st = Pass
	}
	e.add(key, crit, st, "%.0f of %.0f samples at a %s scrape (%.1f%%) (`%s`)", v, want, e.c.ScrapeInterval, 100*v/want, query)
}

// steps5m is how many 5m subquery steps the window holds.
func (e *evaluator) steps5m() float64 { return float64(e.c.Window / (5 * time.Minute)) }

// everyStep checks expr (a rate) was above zero at every 5m step of the
// window. A subquery has no point at a step with no data, so a minimum over
// it cannot see a gap; a count of the steps above zero can.
func (e *evaluator) everyStep(key, crit, label, expr string) (string, Status, bool) {
	query := fmt.Sprintf(`count_over_time((%s > 0)[%s:5m])`, expr, e.w())
	v, _, ok := e.q(key, crit, query, e.c.At)
	if !ok {
		return "", "", false
	}
	st := Fail
	if v >= e.steps5m() {
		st = Pass
	}
	return fmt.Sprintf("%s above zero at %.0f of %.0f 5m steps", label, v, e.steps5m()), st, true
}

// held checks the rollout read exactly percent on every instance for the
// whole window.
func (e *evaluator) held(percent int) {
	key, crit := "rollout-held", fmt.Sprintf("signalman_rollout_percent at %d%% for the whole %s", percent, e.w())
	qlo := fmt.Sprintf("min(min_over_time(signalman_rollout_percent[%s]))", e.w())
	qhi := fmt.Sprintf("max(max_over_time(signalman_rollout_percent[%s]))", e.w())
	lo, p1, ok := e.q(key, crit, qlo, e.c.At)
	if !ok {
		return
	}
	hi, p2, ok := e.q(key, crit, qhi, e.c.At)
	if !ok {
		return
	}
	if !p1 || !p2 {
		e.add(key, crit, Unchecked, "signalman_rollout_percent has no series: is signalmand scraped?")
		return
	}
	st := Fail
	if lo == float64(percent) && hi == float64(percent) {
		st = Pass
	}
	e.add(key, crit, st, "min %g, max %g over %s", lo, hi, e.w())
}

// engines checks both engines evaluated every event: each one's verdict
// rate was above zero at every 5m step of the window, and their verdict
// counts agree.
func (e *evaluator) engines() {
	key, crit := "engines-continuous", "v1 and v2 both produced verdicts at every 5m step of the window"
	var ev []string
	st := Pass
	for _, eng := range []string{engineV1, engineV2} {
		expr := fmt.Sprintf(`sum(rate(signalman_verdicts_total{engine=%q}[5m]))`, eng)
		got, s, ok := e.everyStep(key, crit, eng, expr)
		if !ok {
			return
		}
		if s != Pass {
			st = Fail
		}
		ev = append(ev, got)
	}
	e.add(key, crit, st, "%s", strings.Join(ev, "; "))

	key, crit = "engines-cover", fmt.Sprintf("v2 and v1 wrote the same number of verdicts within %g", e.c.VerdictTolerance)
	var n [2]float64
	for i, eng := range []string{engineV1, engineV2} {
		query := fmt.Sprintf(`sum(increase(signalman_verdicts_total{engine=%q}[%s]))`, eng, e.w())
		v, _, ok := e.q(key, crit, query, e.c.At)
		if !ok {
			return
		}
		n[i] = v
	}
	if n[0] == 0 {
		e.add(key, crit, Fail, "v1 wrote no verdicts over %s", e.w())
		return
	}
	ratio := n[1] / n[0]
	st = Fail
	if math.Abs(ratio-1) <= e.c.VerdictTolerance {
		st = Pass
	}
	e.add(key, crit, st, "v1 %.0f, v2 %.0f verdicts over %s: ratio %.5f", n[0], n[1], e.w(), ratio)
}

// live is the checks every windowed gate starts with: signalmand and the
// differ scraped for the window, the rollout held, both engines evaluating,
// and the differ clean.
func (e *evaluator) live(percent int) {
	e.coverage("coverage-signalmand", "signalmand", "signalman_rollout_percent", e.c.At)
	e.coverage("coverage-differ", "the differ", "signalman_differ_events_total", e.c.At)
	e.held(percent)
	e.engines()
	e.differ()
}

// differ checks the differ compared events for the whole window, kept up
// with the pipeline, and counted no divergence. Activity somewhere in the
// window is not enough: a differ that stalls after an hour counts no
// divergence for the rest of it.
func (e *evaluator) differ() {
	key, crit := "differ-running", "the differ resolved events at every 5m step of the window"
	if got, st, ok := e.everyStep(key, crit, "differ resolutions", "sum(rate(signalman_differ_events_total[5m]))"); ok {
		e.add(key, crit, st, "%s", got)
	}
	e.keepsUp()
	e.zero("divergences", "no v2 false negative, v2 false positive, or missing verdict", "signalman_divergences_counted_total")
	e.zero("shadow-failures", "the shadow engine never failed on an event", "signalman_shadow_failures_total")
}

// keepsUp checks the differ resolved at least as many events over the
// window as the pipeline evaluated, within VerdictTolerance: every admitted
// event is a drop or one record per engine, and the differ resolves each
// record pair once. A differ far behind has not compared the events it
// will report on, so its flat divergence count says nothing about them.
// Only a shortfall fails; a differ catching up a backlog resolves more.
func (e *evaluator) keepsUp() {
	key := "differ-keeps-up"
	crit := fmt.Sprintf("the differ resolved the events signalmand evaluated (ingested less dropped) within %g", e.c.VerdictTolerance)
	qd := fmt.Sprintf("sum(increase(signalman_differ_events_total[%s]))", e.w())
	qi := fmt.Sprintf("sum(increase(signalman_events_ingested_total[%s]))", e.w())
	qx := fmt.Sprintf("sum(increase(signalman_events_dropped_total[%s]))", e.w())
	resolved, _, ok := e.q(key, crit, qd, e.c.At)
	if !ok {
		return
	}
	ingested, present, ok := e.q(key, crit, qi, e.c.At)
	if !ok {
		return
	}
	if !present {
		e.add(key, crit, Unchecked, "signalman_events_ingested_total has no series: is signalmand scraped? (`%s`)", qi)
		return
	}
	// A pipeline that dropped nothing exports no drops series.
	dropped, _, ok := e.q(key, crit, qx, e.c.At)
	if !ok {
		return
	}
	evaluated := ingested - dropped
	if evaluated <= 0 {
		e.add(key, crit, Fail, "signalmand evaluated no events over %s", e.w())
		return
	}
	st := Fail
	if resolved >= (1-e.c.VerdictTolerance)*evaluated {
		st = Pass
	}
	e.add(key, crit, st, "differ resolved %.0f of %.0f events evaluated over %s (%.5f)", resolved, evaluated, e.w(), resolved/evaluated)
}

// alertVolume compares each rule's alert count over the window ending at At
// with the window ending at base. Counts are treated as Poisson: a rule
// fails when the two differ by more than NoiseSigma standard deviations of
// their difference, sqrt(a+b).
func (e *evaluator) alertVolume(base time.Time, against string) {
	key := "alert-volume"
	crit := fmt.Sprintf("alert volume per rule unchanged within %g sigma of %s", e.c.NoiseSigma, against)
	query := fmt.Sprintf(`sum by (rule_id) (increase(signalman_alerts_total[%s]))`, e.w())
	byRule := func(at time.Time) (map[string]float64, bool) {
		ss, err := e.c.Source.Query(e.ctx, query, at)
		if err != nil {
			e.add(key, crit, Unchecked, "query %s at %s: %v", query, at.Format(time.RFC3339), err)
			return nil, false
		}
		m := map[string]float64{}
		for _, s := range ss {
			m[s.Labels["rule_id"]] += s.Value
		}
		return m, true
	}
	e.coverage("coverage-baseline", "signalmand, in "+against+",", "signalman_rollout_percent", base)
	now, ok := byRule(e.c.At)
	if !ok {
		return
	}
	then, ok := byRule(base)
	if !ok {
		return
	}
	ids := map[string]bool{}
	for id := range now {
		ids[id] = true
	}
	for id := range then {
		ids[id] = true
	}
	if len(ids) == 0 {
		e.add(key, crit, Unchecked, "no alerts in either window (`%s`)", query)
		return
	}
	type off struct {
		id   string
		a, b float64
		z    float64
	}
	var outs []off
	for id := range ids {
		a, b := now[id], then[id]
		if a+b == 0 {
			continue
		}
		if z := math.Abs(a-b) / math.Sqrt(a+b); z > e.c.NoiseSigma {
			outs = append(outs, off{id, a, b, z})
		}
	}
	sort.Slice(outs, func(i, j int) bool { return outs[i].z > outs[j].z })
	if len(outs) == 0 {
		e.add(key, crit, Pass, "%d rules compared, %s ending %s against %s ending %s; none moved beyond %g sigma",
			len(ids), e.w(), e.c.At.Format(time.RFC3339), e.w(), base.Format(time.RFC3339), e.c.NoiseSigma)
		return
	}
	var ex []string
	for i, o := range outs {
		if i == 5 {
			ex = append(ex, fmt.Sprintf("and %d more", len(outs)-5))
			break
		}
		ex = append(ex, fmt.Sprintf("%s %.0f now vs %.0f before (%.1f sigma)", o.id, o.a, o.b, o.z))
	}
	e.add(key, crit, Fail, "%d of %d rules moved beyond %g sigma: %s", len(outs), len(ids), e.c.NoiseSigma, strings.Join(ex, "; "))
}

// rollback checks a measured rollback under budget, run at this gate's
// step (from percent) and written within DrillSlack of the hold. A drill
// from another step, or from long before or after the hold, says nothing
// about rolling back from this one. from100 also requires it to go to 0,
// as G4 does.
func (e *evaluator) rollback(key string, percent int, from100 bool) {
	crit := fmt.Sprintf("a rollback measured to take effect in under %s", e.c.RollbackBudget)
	if from100 {
		crit = fmt.Sprintf("a rollback from 100%% measured to take effect in under %s", e.c.RollbackBudget)
	}
	if e.c.Drill == nil || e.c.Drill.Rollback == nil {
		e.add(key, crit, Unchecked, "no game day result: run `cutover gameday` and pass its output with -drill")
		return
	}
	s := e.c.Drill.Rollback
	lo, hi := e.c.At.Add(-e.c.Window-e.c.DrillSlack), e.c.At.Add(e.c.DrillSlack)
	switch {
	case s.From != percent:
		e.add(key, crit, Fail, "%s: rollback was from %d%%; this gate's step is %d%%", e.drillName(), s.From, percent)
	case s.WrittenAt.Before(lo) || s.WrittenAt.After(hi):
		e.add(key, crit, Fail, "%s: rollback written %s, more than %s outside the %s ending %s",
			e.drillName(), s.WrittenAt.UTC().Format(time.RFC3339), e.c.DrillSlack, e.w(), e.c.At.UTC().Format(time.RFC3339))
	default:
		e.stepCheck(key, crit, s, from100, false)
	}
}

func (e *evaluator) stepCheck(key, crit string, s *Step, from100, forward bool) {
	switch {
	case !s.Measured():
		e.add(key, crit, Fail, "%s: %s", e.drillName(), s.String())
	case from100 && !forward && (s.From != 100 || s.To != 0):
		e.add(key, crit, Fail, "%s: rollback was %d%% to %d%%, this gate needs 100%% to 0%%", e.drillName(), s.From, s.To)
	case forward && (s.From != 0 || s.To != 100):
		e.add(key, crit, Fail, "%s: roll-forward was %d%% to %d%%, this gate needs 0%% to 100%%", e.drillName(), s.From, s.To)
	case !forward && s.To >= s.From:
		e.add(key, crit, Fail, "%s: %d%% to %d%% is not a rollback", e.drillName(), s.From, s.To)
	case s.Duration() >= e.c.RollbackBudget:
		e.add(key, crit, Fail, "%s: %s", e.drillName(), s.String())
	default:
		e.add(key, crit, Pass, "%s: %s", e.drillName(), s.String())
	}
}

func (e *evaluator) drillName() string {
	if e.c.DrillFile != "" {
		return e.c.DrillFile
	}
	return "game day"
}

func (e *evaluator) g0() {
	e.replay()
	crit := fmt.Sprintf("the differential fuzzer compared at least %d cases", e.c.FuzzMin)
	if e.c.FuzzStats == "" {
		e.add("fuzz-compared", crit, Unchecked, "pass -fuzz-stats, the directory `make fuzz-differential` sums")
	} else if s, err := ReadFuzzStats(e.c.FuzzStats); err != nil {
		e.add("fuzz-compared", crit, Unchecked, "%v", err)
	} else {
		st := Fail
		if s.Compared >= e.c.FuzzMin {
			st = Pass
		}
		e.add("fuzz-compared", crit, st, "%s: %d workers, %d compared, %d rejected by both, %d suppressed, %d oracle timeouts, %d skipped",
			e.c.FuzzStats, s.Workers, s.Compared, s.RejectedByBoth, s.Suppressed, s.OracleTimeout, s.Skipped)
	}
	e.manual("fuzz-clean", "the differential fuzz run exited 0 with no new crasher",
		"the counters do not record the exit status; cite the run")
	crit = "property and equivalence tests green (determinism, rule independence, prefilter and gate soundness, idempotence)"
	if e.c.RunTests == nil {
		e.add("property-tests", crit, Unchecked, "pass -go-test to run them from the module root")
	} else if out, err := e.c.RunTests(e.ctx); err != nil {
		e.add("property-tests", crit, Fail, "%v: %s", err, tail(out, 5))
	} else {
		e.add("property-tests", crit, Pass, "%s", tail(out, 5))
	}
}

func (e *evaluator) replay() {
	key, crit := "replay-digests", "full corpus replay: v1 and v2 verdict digests match on every partition"
	if e.c.Corpus == "" || e.c.Rules == "" {
		e.add(key, crit, Unchecked, "pass -corpus, -rules and -taxonomy")
		return
	}
	tax, err := sigma.LoadTaxonomy(e.c.Taxonomy)
	if err != nil {
		e.add(key, crit, Unchecked, "taxonomy: %v", err)
		return
	}
	rs, rejected, err := sigma.LoadRuleSet(e.c.Rules, tax)
	if err != nil {
		e.add(key, crit, Unchecked, "rules: %v", err)
		return
	}
	ces, err := corpus.Read(e.c.Corpus)
	if err != nil {
		e.add(key, crit, Unchecked, "corpus: %v", err)
		return
	}
	evs := make([]*event.Event, len(ces))
	for i := range ces {
		evs[i] = ces[i].Event
	}
	r, err := ReplayCorpus(rs, evs, e.c.Partitions)
	if err != nil {
		e.add(key, crit, Unchecked, "replay: %v", err)
		return
	}
	st := Pass
	if len(r.Mismatched()) > 0 {
		st = Fail
	}
	e.add(key, crit, st, "%s; %d rules rejected at load; corpus %s", digestSummary(r), len(rejected), e.c.Corpus)
}

func (e *evaluator) g1() {
	e.live(0)
	e.manual("v2-p99", "v2 p99 match latency under 400 µs under production load",
		"no per-engine match latency metric is exported; take it from the load harness run at production rate")
}

// step is G2 (1%), G3 (10%, 50%) and G4 (100%): held for the window, both
// engines evaluating, the differ clean, alert volume unchanged, and a
// measured rollback.
func (e *evaluator) step(percent int, full bool) {
	e.live(percent)
	if full {
		// With v2 serving every rule, v1 serves an alert only when v2
		// failed on the event, and shadow-failures above is zero.
		e.zero("v1-serves-none", "v1 served no alert: v2 serves every rule", `signalman_alerts_total{engine="v1"}`)
		e.manual("flag-only", "no configuration change other than the rollout flag since G3",
			"compare the deployed configuration with the one G3 ran under")
	} else {
		e.alertVolume(e.c.At.Add(-e.c.Window), "the window before")
	}
	e.rollback("rollback", percent, full)
}

func (e *evaluator) g5() {
	d := e.c.Drill
	if d == nil || d.Rollback == nil || d.RollForward == nil {
		e.add("gameday", "a game day result with a rollback and a roll-forward", Unchecked,
			"no complete game day result: run `cutover gameday` and pass its output with -drill")
		return
	}
	e.stepCheck("rollback", fmt.Sprintf("rolled back from 100%% to 0%% in under %s", e.c.RollbackBudget), d.Rollback, true, false)
	e.stepCheck("roll-forward", fmt.Sprintf("rolled forward from 0%% to 100%% in under %s", e.c.RollbackBudget), d.RollForward, true, true)

	start := d.Rollback.WrittenAt.In(e.c.Location)
	crit := fmt.Sprintf("started during business hours, %02d:00 to %02d:00 on a weekday in %s", e.c.BusinessStart, e.c.BusinessEnd, e.c.Location)
	st := Fail
	if wd := start.Weekday(); wd != time.Saturday && wd != time.Sunday && start.Hour() >= e.c.BusinessStart && start.Hour() < e.c.BusinessEnd {
		st = Pass
	}
	e.add("business-hours", crit, st, "rollback written %s", start.Format("Mon 2006-01-02 15:04:05 MST"))

	crit = fmt.Sprintf("at full traffic: ingest rate at the rollback at least %g of the 7 day mean", e.c.FullTraffic)
	qNow := `sum(rate(signalman_events_ingested_total[5m]))`
	qMean := `sum(rate(signalman_events_ingested_total[7d]))`
	at := d.Rollback.WrittenAt
	now, p1, ok := e.q("full-traffic", crit, qNow, at)
	if !ok {
		return
	}
	mean, p2, ok := e.q("full-traffic", crit, qMean, at)
	if !ok {
		return
	}
	if !p1 || !p2 || mean == 0 {
		e.add("full-traffic", crit, Unchecked, "no ingest rate at %s", at.Format(time.RFC3339))
		return
	}
	st = Fail
	if now >= e.c.FullTraffic*mean {
		st = Pass
	}
	e.add("full-traffic", crit, st, "%.0f ev/s at the rollback, 7 day mean %.0f ev/s (%.2f)", now, mean, now/mean)
}

func (e *evaluator) g6() {
	e.live(100)
	// A flat violations counter is also what an audit that never ran
	// exports, so the audit must have closed windows at every step.
	key, crit := "audit-running", "the invariant 1 audit closed windows at every 5m step of the window"
	if got, st, ok := e.everyStep(key, crit, "audit windows", "sum(rate(signalman_audit_windows_total[5m]))"); ok {
		e.add(key, crit, st, "%s", got)
	}
	e.zero("audit-violations", "the invariant 1 audit found nothing", "signalman_audit_violations_total")

	key, crit = "skew-in-reloads", "every version_skew divergence falls inside a reload"
	query := fmt.Sprintf(`sum(increase(signalman_divergences_total{class="version_skew"}[%s]))`, e.w())
	if v, _, ok := e.q(key, crit, query, e.c.At); ok {
		if v == 0 {
			e.add(key, crit, Pass, "no version_skew over %s (`%s`)", e.w(), query)
		} else {
			e.manual(key, crit, fmt.Sprintf("%g version_skew records over %s; match each to a reload in the differ log", v, e.w()))
		}
	}
	e.manual("v2-p99", "v2 p99 match latency under 400 µs under production load for the whole period",
		"no per-engine match latency metric is exported; take it from the load harness run at production rate")
	if e.c.BaselineAt.IsZero() {
		e.add("alert-volume", "alert volume per rule while v2 serves matches the volume while v1 served", Unchecked,
			"pass -baseline-at, the end of a window as long as this one in which v1 served every rule")
	} else {
		e.alertVolume(e.c.BaselineAt, "the v1 baseline")
	}

	d := e.c.Drill
	if d == nil || d.Rollback == nil || d.RollForward == nil {
		e.add("gameday", "the G5 game day rolled back and forward under budget", Unchecked,
			"pass the G5 game day result with -drill")
	} else {
		e.stepCheck("gameday-rollback", fmt.Sprintf("the game day rollback took under %s", e.c.RollbackBudget), d.Rollback, true, false)
		e.stepCheck("gameday-roll-forward", fmt.Sprintf("the game day roll-forward took under %s", e.c.RollbackBudget), d.RollForward, true, true)
	}

	crit = "G0 through G5 each have a date in docs/cutover.md"
	if e.c.Doc == "" {
		e.add("ladder-dated", crit, Unchecked, "pass -doc")
	} else {
		dates := LadderDates(e.c.Doc)
		var missing []string
		for _, g := range Gates[:6] {
			if dates[g] == "" {
				missing = append(missing, g)
			}
		}
		if len(missing) == 0 {
			e.add("ladder-dated", crit, Pass, "dates: %s", ladderSummary(dates))
		} else {
			e.add("ladder-dated", crit, Fail, "no date for %s", strings.Join(missing, ", "))
		}
		crit = "every divergence log entry has a root cause and a fix, and none is open"
		open, n := OpenDivergences(e.c.Doc)
		if len(open) == 0 {
			e.add("divergence-log", crit, Pass, "%d entries, none open", n)
		} else {
			e.add("divergence-log", crit, Fail, "%d of %d entries open: %s", len(open), n, strings.Join(open, ", "))
		}
	}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
