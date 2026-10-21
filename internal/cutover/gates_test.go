package cutover

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var checkAt = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// healthy fills the queries every live gate shares with a clean run over
// window w: both engines writing the same verdicts, the differ comparing,
// nothing diverging.
func healthy(f *fakeSource, w string, percent float64) {
	f.instant[fmt.Sprintf("min(min_over_time(signalman_rollout_percent[%s]))", w)] = percent
	f.instant[fmt.Sprintf("max(max_over_time(signalman_rollout_percent[%s]))", w)] = percent
	d, err := time.ParseDuration(w)
	if err != nil {
		panic(err)
	}
	for _, eng := range []string{"v1", "v2"} {
		f.instant[fmt.Sprintf(`count_over_time((sum(rate(signalman_verdicts_total{engine=%q}[5m])) > 0)[%s:5m])`, eng, w)] = float64(d / (5 * time.Minute))
		f.instant[fmt.Sprintf(`sum(increase(signalman_verdicts_total{engine=%q}[%s]))`, eng, w)] = 1e9
	}
	// Every scrape of the window landed.
	f.instant[fmt.Sprintf("min(count_over_time(signalman_rollout_percent[%s]))", w)] = float64(d / (15 * time.Second))
	f.instant[fmt.Sprintf("min(count_over_time(signalman_differ_events_total[%s]))", w)] = float64(d / (15 * time.Second))
	f.instant[fmt.Sprintf("sum(increase(signalman_differ_events_total[%s]))", w)] = 1e6
	f.instant[fmt.Sprintf("sum(increase(signalman_divergences_counted_total[%s]))", w)] = 0
	f.instant[fmt.Sprintf("sum(increase(signalman_shadow_failures_total[%s]))", w)] = 0
}

func statusOf(t *testing.T, r Report, key string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Key == key {
			return c
		}
	}
	t.Fatalf("%s has no %s check: %+v", r.Name(), key, r.Checks)
	return Check{}
}

func eval(t *testing.T, c Config) Report {
	t.Helper()
	if c.At.IsZero() {
		c.At = checkAt
	}
	if c.Now == nil {
		c.Now = func() time.Time { return checkAt.Add(time.Hour) }
	}
	r, err := Evaluate(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestG1PassesOnlyWithTheManualCheckAttested(t *testing.T) {
	f := newFake()
	healthy(f, "168h", 0)
	r := eval(t, Config{Gate: "G1", Source: f})
	for _, c := range r.Checks {
		if c.Key != "v2-p99" && c.Status != Pass {
			t.Errorf("%s: %s %s", c.Key, c.Status, c.Evidence)
		}
	}
	if p := statusOf(t, r, "v2-p99"); p.Status != Unchecked || !p.Manual {
		t.Fatalf("p99 %+v", p)
	}
	if r.Passed() {
		t.Fatal("G1 passed with an unchecked criterion")
	}
	r = eval(t, Config{Gate: "G1", Source: f, Attest: map[string]string{"v2-p99": "load run 2026-11-01, p99 210us"}})
	if !r.Passed() || statusOf(t, r, "v2-p99").Status != Attested {
		t.Fatalf("attested G1 did not pass: %+v", r.Checks)
	}
}

func TestG1FailsOnADivergence(t *testing.T) {
	f := newFake()
	healthy(f, "168h", 0)
	f.instant["sum(increase(signalman_divergences_counted_total[168h]))"] = 1
	r := eval(t, Config{Gate: "G1", Source: f, Attest: map[string]string{"v2-p99": "x"}})
	if r.Passed() || statusOf(t, r, "divergences").Status != Fail {
		t.Fatal("one divergence must fail G1")
	}
}

// A differ nobody scrapes exports no series, which is not zero divergences.
func TestAnUnscrapedDifferIsUnchecked(t *testing.T) {
	f := newFake()
	healthy(f, "168h", 0)
	delete(f.instant, "sum(increase(signalman_divergences_counted_total[168h]))")
	r := eval(t, Config{Gate: "G1", Source: f})
	if c := statusOf(t, r, "divergences"); c.Status != Unchecked || !strings.Contains(c.Evidence, "scraped") {
		t.Fatalf("divergences %+v", c)
	}
}

func TestAFailedQueryIsUnchecked(t *testing.T) {
	f := newFake()
	healthy(f, "168h", 0)
	f.errs["sum(increase(signalman_shadow_failures_total[168h]))"] = errors.New("connection refused")
	r := eval(t, Config{Gate: "G1", Source: f})
	if c := statusOf(t, r, "shadow-failures"); c.Status != Unchecked || !strings.Contains(c.Evidence, "connection refused") {
		t.Fatalf("shadow-failures %+v", c)
	}
}

func TestEnginesMustCoverEachOther(t *testing.T) {
	f := newFake()
	healthy(f, "168h", 0)
	f.instant[`sum(increase(signalman_verdicts_total{engine="v2"}[168h]))`] = 0.99e9
	f.instant[`count_over_time((sum(rate(signalman_verdicts_total{engine="v2"}[5m])) > 0)[168h:5m])`] = 2015
	r := eval(t, Config{Gate: "G1", Source: f})
	if statusOf(t, r, "engines-cover").Status != Fail || statusOf(t, r, "engines-continuous").Status != Fail {
		t.Fatalf("a v2 short of v1's verdicts, with a gap, passed: %+v", r.Checks)
	}
}

func TestAttestingAnUnknownKeyIsAnError(t *testing.T) {
	f := newFake()
	healthy(f, "168h", 0)
	if _, err := Evaluate(context.Background(), Config{Gate: "G1", At: checkAt, Source: f, Attest: map[string]string{"p99": "x"}}); err == nil {
		t.Fatal("a typo in -attest must not pass silently")
	}
}

func TestAFailedCheckCannotBeAttested(t *testing.T) {
	f := newFake()
	healthy(f, "168h", 0)
	f.instant["sum(increase(signalman_divergences_counted_total[168h]))"] = 2
	r := eval(t, Config{Gate: "G1", Source: f, Attest: map[string]string{"divergences": "looked fine", "v2-p99": "x"}})
	if statusOf(t, r, "divergences").Status != Fail || r.Passed() {
		t.Fatal("an attestation overrode a failed check")
	}
}

func stepDrill(from, to int, seconds float64) *Drill {
	w := checkAt.Add(-time.Hour)
	eff := w.Add(time.Duration(seconds * float64(time.Second)))
	return &Drill{Rollback: &Step{From: from, To: to, WrittenAt: w, TookEffectAt: &eff, FirstNewAlertAt: &eff, Seconds: &seconds}}
}

func alertsByRule(f *fakeSource, t time.Time, counts map[string]float64) {
	var v []Sample
	for id, n := range counts {
		v = append(v, Sample{Labels: map[string]string{"rule_id": id}, Value: n})
	}
	f.vectors[at(`sum by (rule_id) (increase(signalman_alerts_total[48h]))`, t)] = v
}

func TestG2(t *testing.T) {
	f := newFake()
	healthy(f, "48h", 1)
	alertsByRule(f, checkAt, map[string]float64{"a": 1000, "b": 10, "c": 0})
	alertsByRule(f, checkAt.Add(-48*time.Hour), map[string]float64{"a": 1040, "b": 12, "c": 1})

	r := eval(t, Config{Gate: "G2", Source: f, Drill: stepDrill(1, 0, 6)})
	if !r.Passed() {
		t.Fatalf("G2 did not pass: %+v", r.Checks)
	}

	// Without a measured rollback G2 cannot pass.
	r = eval(t, Config{Gate: "G2", Source: f})
	if c := statusOf(t, r, "rollback"); c.Status != Unchecked || r.Passed() {
		t.Fatalf("rollback %+v", c)
	}
	// A rollback over budget fails it.
	r = eval(t, Config{Gate: "G2", Source: f, Drill: stepDrill(1, 0, 31)})
	if statusOf(t, r, "rollback").Status != Fail {
		t.Fatal("a 31s rollback passed a 30s budget")
	}
	// A rollout that moved during the hold fails it.
	f.instant["max(max_over_time(signalman_rollout_percent[48h]))"] = 10
	r = eval(t, Config{Gate: "G2", Source: f, Drill: stepDrill(1, 0, 6)})
	if statusOf(t, r, "rollout-held").Status != Fail {
		t.Fatal("a rollout that reached 10% held at 1%")
	}
}

func TestAlertVolumeOutsideNoiseFails(t *testing.T) {
	f := newFake()
	healthy(f, "48h", 10)
	alertsByRule(f, checkAt, map[string]float64{"a": 1000, "b": 400})
	alertsByRule(f, checkAt.Add(-48*time.Hour), map[string]float64{"a": 1010, "b": 200})
	r := eval(t, Config{Gate: "G3", Percent: 10, Source: f, Drill: stepDrill(10, 1, 4)})
	c := statusOf(t, r, "alert-volume")
	if c.Status != Fail || !strings.Contains(c.Evidence, "b 400 now vs 200 before") || strings.Contains(c.Evidence, "a 1000") {
		t.Fatalf("alert-volume %+v", c)
	}
	if r.Name() != "G3 10%" {
		t.Fatalf("name %q", r.Name())
	}
}

func TestG3NeedsAStep(t *testing.T) {
	for _, p := range []int{0, 1, 25, 100} {
		if _, err := Evaluate(context.Background(), Config{Gate: "G3", Percent: p, At: checkAt, Source: newFake()}); err == nil {
			t.Fatalf("G3 at %d%% accepted", p)
		}
	}
	if _, err := Evaluate(context.Background(), Config{Gate: "G2", Percent: 10, At: checkAt, Source: newFake()}); err == nil {
		t.Fatal("-percent accepted outside G3")
	}
	if _, err := Evaluate(context.Background(), Config{Gate: "G7", At: checkAt, Source: newFake()}); err == nil {
		t.Fatal("unknown gate accepted")
	}
}

func TestG4(t *testing.T) {
	f := newFake()
	healthy(f, "48h", 100)
	attest := map[string]string{"flag-only": "deploy diff empty"}
	r := eval(t, Config{Gate: "G4", Source: f, Drill: stepDrill(100, 0, 9), Attest: attest})
	if !r.Passed() {
		t.Fatalf("G4: %+v", r.Checks)
	}
	if c := statusOf(t, r, "v1-serves-none"); c.Status != Pass {
		t.Fatalf("v1 alerts with no series is zero: %+v", c)
	}
	// A rollback exercised at 1% does not show it still works at 100%.
	r = eval(t, Config{Gate: "G4", Source: f, Drill: stepDrill(1, 0, 9), Attest: attest})
	if statusOf(t, r, "rollback").Status != Fail {
		t.Fatal("a 1% rollback satisfied G4")
	}
	f.instant[`sum(increase(signalman_alerts_total{engine="v1"}[48h]))`] = 3
	r = eval(t, Config{Gate: "G4", Source: f, Drill: stepDrill(100, 0, 9), Attest: attest})
	if statusOf(t, r, "v1-serves-none").Status != Fail {
		t.Fatal("v1 served alerts at 100%")
	}
}

func gameDay(start time.Time, back, fwd float64) *Drill {
	mk := func(from, to int, w time.Time, s float64) *Step {
		eff := w.Add(time.Duration(s * float64(time.Second)))
		return &Step{From: from, To: to, WrittenAt: w, TookEffectAt: &eff, FirstNewAlertAt: &eff, Seconds: &s}
	}
	return &Drill{StartedAt: start, Rollback: mk(100, 0, start, back), RollForward: mk(0, 100, start.Add(5*time.Minute), fwd)}
}

func trafficAt(f *fakeSource, t time.Time, now, mean float64) {
	f.instant[at(`sum(rate(signalman_events_ingested_total[5m]))`, t)] = now
	f.instant[at(`sum(rate(signalman_events_ingested_total[7d]))`, t)] = mean
}

func TestG5(t *testing.T) {
	tue := time.Date(2026, 11, 3, 14, 0, 0, 0, time.UTC)
	f := newFake()
	trafficAt(f, tue, 48000, 50000)
	r := eval(t, Config{Gate: "G5", Source: f, Drill: gameDay(tue, 8, 11)})
	if !r.Passed() {
		t.Fatalf("G5: %+v", r.Checks)
	}

	sat := time.Date(2026, 11, 7, 14, 0, 0, 0, time.UTC)
	trafficAt(f, sat, 48000, 50000)
	if r := eval(t, Config{Gate: "G5", Source: f, Drill: gameDay(sat, 8, 11)}); statusOf(t, r, "business-hours").Status != Fail {
		t.Fatal("a Saturday game day is not during business hours")
	}
	night := time.Date(2026, 11, 3, 3, 0, 0, 0, time.UTC)
	trafficAt(f, night, 10000, 50000)
	r = eval(t, Config{Gate: "G5", Source: f, Drill: gameDay(night, 8, 11)})
	if statusOf(t, r, "business-hours").Status != Fail || statusOf(t, r, "full-traffic").Status != Fail {
		t.Fatalf("a 3am game day at a fifth of the traffic passed: %+v", r.Checks)
	}
	// Business hours are local to the SOC.
	ny, err := time.LoadLocation("America/New_York")
	if err == nil {
		if r := eval(t, Config{Gate: "G5", Source: f, Drill: gameDay(tue, 8, 11), Location: ny}); statusOf(t, r, "business-hours").Status != Pass {
			t.Fatal("14:00 UTC is 09:00 in New York")
		}
	}
	if r := eval(t, Config{Gate: "G5", Source: f, Drill: gameDay(tue, 8, 31)}); statusOf(t, r, "roll-forward").Status != Fail {
		t.Fatal("a 31s roll-forward passed")
	}
	if r := eval(t, Config{Gate: "G5", Source: f, Drill: stepDrill(100, 0, 8)}); r.Passed() {
		t.Fatal("a game day with no roll-forward passed")
	}
}

const ladderDoc = `# Equivalence and cutover

## Gate ladder

| Gate | Criteria | Date passed |
|---|---|---|
| G0 Offline equivalence | a | 2026-09-01 |
| G1 Shadow at full traffic | b | 2026-09-10 |
| G2 1% of rules served by v2 | c | 2026-09-12 |
| G3 10%, then 50% | d | 2026-09-16 |
| G4 100% served by v2 | e | 2026-09-18 |
| G5 Rollback game day | f | 2026-09-19 |
| G6 Retirement | g | |

## Divergence log

| # | Found | Class | Rule | Event (partition/seq) | Root cause | Fix | Status |
|---|---|---|---|---|---|---|---|
| 1 | 2026-09-03 | v2_false_negative | r | 3/81723 | prefilter harvested under not | derive only conjunctive literals | fixed |

## Gate evidence

Nothing recorded. No gate has been checked against production traffic.
`

func TestG6(t *testing.T) {
	f := newFake()
	healthy(f, "336h", 100)
	tue := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)
	base := checkAt.Add(-60 * 24 * time.Hour)
	q := `sum by (rule_id) (increase(signalman_alerts_total[336h]))`
	f.vectors[at(q, checkAt)] = []Sample{{Labels: map[string]string{"rule_id": "a"}, Value: 7000}}
	f.vectors[at(q, base)] = []Sample{{Labels: map[string]string{"rule_id": "a"}, Value: 7100}}
	cfg := Config{Gate: "G6", Source: f, Drill: gameDay(tue, 8, 11), Doc: ladderDoc, BaselineAt: base,
		Attest: map[string]string{"v2-p99": "load run"}}
	r := eval(t, cfg)
	if !r.Passed() {
		t.Fatalf("G6: %+v", r.Checks)
	}
	if c := statusOf(t, r, "skew-in-reloads"); c.Status != Pass {
		t.Fatalf("zero skew needs no attestation: %+v", c)
	}

	f.instant[`sum(increase(signalman_divergences_total{class="version_skew"}[336h]))`] = 4
	r = eval(t, cfg)
	if c := statusOf(t, r, "skew-in-reloads"); c.Status != Unchecked || !c.Manual {
		t.Fatalf("skew %+v", c)
	}

	open := strings.Replace(ladderDoc, "| fixed |", "| open |", 1)
	undated := strings.Replace(ladderDoc, "| f | 2026-09-19 |", "| f | |", 1)
	delete(f.instant, `sum(increase(signalman_divergences_total{class="version_skew"}[336h]))`)
	cfg.Doc = open
	if r := eval(t, cfg); statusOf(t, r, "divergence-log").Status != Fail {
		t.Fatal("an open divergence passed G6")
	}
	cfg.Doc = undated
	if r := eval(t, cfg); statusOf(t, r, "ladder-dated").Status != Fail {
		t.Fatal("an undated G5 passed G6")
	}
	cfg.Doc, cfg.BaselineAt = ladderDoc, time.Time{}
	if r := eval(t, cfg); statusOf(t, r, "alert-volume").Status != Unchecked {
		t.Fatal("alert volume without a baseline is unchecked")
	}
}

func TestG0(t *testing.T) {
	stats := t.TempDir()
	for i, n := range []int{60_000_000, 50_000_000} {
		b := fmt.Appendf(nil, `{"compared": %d, "rejected_by_both": 5, "suppressed": 1, "oracle_timeout": 0, "skipped": 9}`, n)
		if err := os.WriteFile(filepath.Join(stats, fmt.Sprintf("w%d.json", i)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ran := false
	cfg := Config{Gate: "G0",
		Rules: "../../cmd/signalman/testdata/pass", Taxonomy: "../../config/taxonomy", Corpus: "../../cmd/signalman/testdata/corpus",
		FuzzStats: stats,
		RunTests: func(context.Context) (string, error) {
			ran = true
			return "ok  \tgithub.com/atontalapur/signalman/internal/engine/v2\t3.1s", nil
		},
		Attest: map[string]string{"fuzz-clean": "nightly 2026-11-01 exit 0"},
	}
	r := eval(t, cfg)
	if !r.Passed() || !ran {
		t.Fatalf("G0: %+v", r.Checks)
	}
	if c := statusOf(t, r, "replay-digests"); !strings.Contains(c.Evidence, "6 events") || !strings.Contains(c.Evidence, "match") {
		t.Fatalf("replay evidence %q", c.Evidence)
	}
	if c := statusOf(t, r, "fuzz-compared"); !strings.Contains(c.Evidence, "110000000 compared") {
		t.Fatalf("fuzz evidence %q", c.Evidence)
	}

	cfg.FuzzMin = 200_000_000
	cfg.RunTests = func(context.Context) (string, error) {
		return "--- FAIL: TestRuleIndependence", errors.New("exit status 1")
	}
	r = eval(t, cfg)
	if statusOf(t, r, "fuzz-compared").Status != Fail || statusOf(t, r, "property-tests").Status != Fail {
		t.Fatalf("G0 short of the fuzz floor with a failing test: %+v", r.Checks)
	}

	r = eval(t, Config{Gate: "G0"})
	for _, k := range []string{"replay-digests", "fuzz-compared", "property-tests"} {
		if statusOf(t, r, k).Status != Unchecked {
			t.Fatalf("%s with no evidence is not unchecked", k)
		}
	}
}

func TestReplayDigestsAgreeAndCount(t *testing.T) {
	r := eval(t, Config{Gate: "G0", Rules: "../../internal/engine/v1/testdata/rules", Taxonomy: "../../internal/engine/v1/testdata/taxonomy",
		Corpus: "../../cmd/signalman/testdata/corpus", Partitions: 4})
	c := statusOf(t, r, "replay-digests")
	if c.Status != Pass || !strings.Contains(c.Evidence, "4 partitions") {
		t.Fatalf("replay %+v", c)
	}
	p := PartitionDigest{V1: "a", V2: "a", V1Verdicts: 3, V2Verdicts: 2}
	if p.Equal() || len((Replay{Partitions: []PartitionDigest{p}}).Mismatched()) != 1 {
		t.Fatal("equal digests over different verdict counts are a mismatch")
	}
}

// A window that ends after now has not happened yet: its queries see only
// the part that did, and -record would date the gate in the future.
func TestAWindowEndingInTheFutureIsRefused(t *testing.T) {
	f := newFake()
	healthy(f, "168h", 0)
	now := func() time.Time { return checkAt.Add(-time.Minute) }
	if _, err := Evaluate(context.Background(), Config{Gate: "G1", At: checkAt, Now: now, Source: f}); err == nil {
		t.Fatal("-at a minute after now accepted")
	}
	r, err := Evaluate(context.Background(), Config{Gate: "G1", Now: now, Source: f})
	if err != nil || !r.At.Equal(now()) {
		t.Fatalf("a zero -at is now: %v %v", r.At, err)
	}
}

// Sums and extremes over a window only see the samples that exist. A
// signalmand or differ scraped for a day of a seven-day hold would pass
// every other check, so each gate needs the window covered.
func TestPartialCoverageFailsTheGate(t *testing.T) {
	for _, tc := range []struct{ query, key string }{
		{"min(count_over_time(signalman_rollout_percent[168h]))", "coverage-signalmand"},
		{"min(count_over_time(signalman_differ_events_total[168h]))", "coverage-differ"},
	} {
		f := newFake()
		healthy(f, "168h", 0)
		f.instant[tc.query] = 40320 * 0.9
		r := eval(t, Config{Gate: "G1", Source: f, Attest: map[string]string{"v2-p99": "x"}})
		if c := statusOf(t, r, tc.key); c.Status != Fail || r.Passed() {
			t.Fatalf("%s at 90%% coverage: %+v", tc.key, c)
		}
		delete(f.instant, tc.query)
		r = eval(t, Config{Gate: "G1", Source: f, Attest: map[string]string{"v2-p99": "x"}})
		if c := statusOf(t, r, tc.key); c.Status == Pass || r.Passed() {
			t.Fatalf("%s with no samples: %+v", tc.key, c)
		}
	}
	f := newFake()
	healthy(f, "168h", 0)
	r := eval(t, Config{Gate: "G1", Source: f, Attest: map[string]string{"v2-p99": "x"}})
	if !r.Passed() {
		t.Fatalf("full coverage: %+v", r.Checks)
	}
}

// One 5m step with no verdicts from an engine is a gap the minimum over
// the steps that exist cannot see.
func TestAnEngineGapFailsTheGate(t *testing.T) {
	f := newFake()
	healthy(f, "48h", 1)
	alertsByRule(f, checkAt, map[string]float64{"a": 1000})
	alertsByRule(f, checkAt.Add(-48*time.Hour), map[string]float64{"a": 1000})
	f.instant[`count_over_time((sum(rate(signalman_verdicts_total{engine="v1"}[5m])) > 0)[48h:5m])`] = 575
	r := eval(t, Config{Gate: "G2", Source: f, Drill: stepDrill(1, 0, 6)})
	if c := statusOf(t, r, "engines-continuous"); c.Status != Fail || !strings.Contains(c.Evidence, "575 of 576") {
		t.Fatalf("engines-continuous %+v", c)
	}
}

// The alert volume baseline is a window too; a half-scraped one is not a
// baseline.
func TestAlertVolumeBaselineNeedsCoverage(t *testing.T) {
	f := newFake()
	healthy(f, "48h", 1)
	alertsByRule(f, checkAt, map[string]float64{"a": 1000})
	alertsByRule(f, checkAt.Add(-48*time.Hour), map[string]float64{"a": 1000})
	q := "min(count_over_time(signalman_rollout_percent[48h]))"
	f.instant[at(q, checkAt)] = 11520
	f.instant[at(q, checkAt.Add(-48*time.Hour))] = 5000
	r := eval(t, Config{Gate: "G2", Source: f, Drill: stepDrill(1, 0, 6)})
	if c := statusOf(t, r, "coverage-baseline"); c.Status != Fail || r.Passed() {
		t.Fatalf("coverage-baseline %+v", c)
	}
}
