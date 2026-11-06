package pipe

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/obs"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"gopkg.in/yaml.v3"
)

// A rule's rule_matches_total series must exist from the moment the rule is
// loaded, at zero. SignalmanRuleWentSilent compares increase() over 24h and
// 30d; a taxonomy change needs a restart, and a rule the change silences
// never matches in the new process. Without the zero, its series would stop
// at the restart, fall out of the 24h window, and the alert would compare
// nothing: the exact failure it exists to catch would never ticket.
func TestRuleMatchesExportsZeroForEveryLoadedRule(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := obs.New(reg)
	rs := loadRules(t)
	slot := NewSlot(V1(rs), m)
	if got := testutil.CollectAndCount(m.RuleMatches); got != len(rs.Rules) {
		t.Fatalf("%d rule_matches_total series for %d rules", got, len(rs.Rules))
	}
	for _, r := range rs.Rules {
		if v := testutil.ToFloat64(m.RuleMatches.WithLabelValues(r.ID)); v != 0 {
			t.Fatalf("rule %s starts at %v", r.ID, v)
		}
	}

	// A reload that drops a rule drops its series: a rule removed on
	// purpose is not a rule gone silent.
	m.RuleMatches.WithLabelValues(rs.Rules[0].ID).Add(3)
	smaller := *rs
	smaller.Rules = rs.Rules[1:]
	smaller.Version = "smaller"
	slot.Store(V1(&smaller))
	if got := testutil.CollectAndCount(m.RuleMatches); got != len(smaller.Rules) {
		t.Fatalf("%d series after dropping a rule, want %d", got, len(smaller.Rules))
	}
	// Reloading the same rules keeps their counts.
	m.RuleMatches.WithLabelValues(rs.Rules[1].ID).Add(2)
	slot.Store(V1(&smaller))
	if v := testutil.ToFloat64(m.RuleMatches.WithLabelValues(rs.Rules[1].ID)); v != 2 {
		t.Fatalf("reload reset a kept rule's count to %v", v)
	}
}

// renamedTaxonomy copies config/taxonomy and renames the event-side field
// CommandLine to ProcessCommandLine in the sysmon process_creation binding:
// the kind of edit that loads cleanly, errors nowhere, and quietly turns off
// every rule that reads the command line on sysmon events.
func renamedTaxonomy(t *testing.T) *sigma.Taxonomy {
	t.Helper()
	dir := t.TempDir()
	ents, err := os.ReadDir(taxonomyDir)
	if err != nil {
		t.Fatal(err)
	}
	renamed := false
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(taxonomyDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if e.Name() == "sysmon.yml" {
			s := strings.Replace(string(b), "CommandLine: CommandLine", "CommandLine: ProcessCommandLine", 1)
			renamed = s != string(b)
			b = []byte(s)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !renamed {
		t.Fatal("config/taxonomy/sysmon.yml no longer maps CommandLine: CommandLine")
	}
	tax, err := sigma.LoadTaxonomy(dir)
	if err != nil {
		t.Fatal(err)
	}
	return tax
}

// fixtureEvents is every match case from the shipped rules' fixtures, as
// raw records, so most rules have something to match.
func fixtureEvents(t *testing.T, at time.Time) []broker.Record {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(shippedRules, "*.test.yml"))
	if err != nil || len(paths) == 0 {
		t.Fatal("no fixtures", err)
	}
	slices.Sort(paths)
	var recs []broker.Record
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Cases []struct {
				Expect string         `yaml:"expect"`
				Event  map[string]any `yaml:"event"`
			} `yaml:"cases"`
		}
		if err := yaml.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		for _, c := range f.Cases {
			if c.Expect != "match" || strings.HasPrefix(filepath.Base(p), "signalman_canary") {
				continue
			}
			c.Event["event_time"] = at.UTC().Format(time.RFC3339Nano)
			body, err := json.Marshal(c.Event)
			if err != nil {
				t.Fatal(err)
			}
			recs = append(recs, rawRecord("host-"+filepath.Base(p), "sysmon", string(body)))
		}
	}
	return recs
}

// sample is one scrape of one rule's counter.
type sample struct {
	at time.Time
	v  float64
}

// increase is PromQL's increase() without extrapolation: the sum of the
// rises between samples in (at-window, at], treating a drop as a counter
// reset. Fewer than two samples is no result, as in PromQL.
func increase(s []sample, at time.Time, window time.Duration) (float64, bool) {
	var in []sample
	for _, x := range s {
		if x.at.After(at.Add(-window)) && !x.at.After(at) {
			in = append(in, x)
		}
	}
	if len(in) < 2 {
		return 0, false
	}
	sum := 0.0
	for i := 1; i < len(in); i++ {
		if d := in[i].v - in[i-1].v; d >= 0 {
			sum += d
		} else {
			sum += in[i].v
		}
	}
	return sum, true
}

// wentSilent is SignalmanRuleWentSilent's expression at one instant:
// increase[24h] == 0 and increase[30d] > 0.
func wentSilent(s []sample, at time.Time) bool {
	day, ok1 := increase(s, at, 24*time.Hour)
	month, ok2 := increase(s, at, 30*24*time.Hour)
	return ok1 && ok2 && day == 0 && month > 0
}

func scrapeRuleMatches(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range fams {
		if f.GetName() != "signalman_rule_matches_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			out[labelValue(m, "rule_id")] = m.GetCounter().GetValue()
		}
	}
	return out
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// The S-52 acceptance. Process one runs three days under the real taxonomy,
// with a replay every six hours and a scrape every hour. Process two
// restarts on a taxonomy with one field renamed and runs two more days.
// Every rule the rename turns off goes silent by SignalmanRuleWentSilent's
// expression; every rule that does not read the renamed field keeps
// matching and does not.
func TestTaxonomyRenameSilencesTheAffectedRule(t *testing.T) {
	mem := newMemory()
	start := time.Unix(1790000000, 0).UTC()
	now := start
	series := map[string][]sample{}
	matchedIn := [2]map[string]float64{}

	runProcess := func(idx int, tax *sigma.Taxonomy, hours int) {
		reg := prometheus.NewRegistry()
		m := obs.New(reg)
		rs, errs, err := sigma.LoadRuleSet(shippedRules, tax)
		if err != nil || len(errs) != 0 {
			t.Fatal(err, errs)
		}
		r := &rig{b: mem, mem: mem, reg: reg, m: m, norm: NewNormalizer(tax, NormalizeConfig{}, m), rs: rs}
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() { errc <- newPipeline(t, r, testConfig()).Run(ctx) }()
		for h := 0; h < hours; h++ {
			if h%6 == 0 {
				if err := mem.Produce(context.Background(), fixtureEvents(t, now)); err != nil {
					t.Fatal(err)
				}
				waitCommitted(t, mem, errc)
			}
			for id, v := range scrapeRuleMatches(t, reg) {
				series[id] = append(series[id], sample{at: now, v: v})
			}
			now = now.Add(time.Hour)
		}
		cancel()
		<-errc
		matchedIn[idx] = scrapeRuleMatches(t, reg)
	}

	runProcess(0, loadTaxonomy(t), 72)
	runProcess(1, renamedTaxonomy(t), 48)
	end := now.Add(-time.Hour) // the last scrape

	ruleText := map[string]string{}
	rs := loadShippedRules(t)
	for _, r := range rs.Rules {
		b, err := os.ReadFile(r.Path)
		if err != nil {
			t.Fatal(err)
		}
		ruleText[r.ID] = string(b)
	}

	var silenced []string
	for _, r := range rs.Rules {
		before, after := matchedIn[0][r.ID], matchedIn[1][r.ID]
		_, exported := matchedIn[1][r.ID]
		if !exported {
			t.Fatalf("rule %s has no rule_matches_total series after the restart", r.Path)
		}
		// for: 1h, evaluated hourly: true now and an hour ago.
		fires := wentSilent(series[r.ID], end) && wentSilent(series[r.ID], end.Add(-time.Hour))
		readsField := strings.Contains(ruleText[r.ID], "CommandLine")
		switch {
		case r.ID == CanaryRuleID:
			// No canary in this test; its rule never matched.
			if fires {
				t.Fatalf("canary rule fired with no history")
			}
		case before > 0 && after == 0:
			if !readsField {
				t.Fatalf("rule %s went quiet but does not read CommandLine", r.Path)
			}
			if !fires {
				t.Fatalf("rule %s matched %v times, then none after the rename, and SignalmanRuleWentSilent did not fire", r.Path, before)
			}
			silenced = append(silenced, filepath.Base(r.Path))
		case before > 0:
			if fires {
				t.Fatalf("rule %s still matches (%v) and fired", r.Path, after)
			}
		default:
			if fires {
				t.Fatalf("rule %s never matched and fired", r.Path)
			}
		}
		if !readsField && before > 0 && after == 0 {
			t.Fatalf("rule %s does not read the renamed field and still went quiet", r.Path)
		}
	}
	if len(silenced) == 0 {
		t.Fatal("the rename silenced no rule; the test proves nothing")
	}
	if !slices.Contains(silenced, "certutil_download.yml") {
		t.Fatalf("certutil_download reads CommandLine on sysmon events and should be among the silenced: %v", silenced)
	}
	t.Logf("silenced by the rename: %v", silenced)
}

// increase() never counts a series' first sample, so an alerts or shadow
// failures series made by its first Add hides that first count. G4 reads
// signalman_alerts_total{engine="v1"} at 100% and G1 to G4 read
// signalman_shadow_failures_total; both must exist at zero, per rule and
// engine, as soon as the engines are stored.
func TestAlertsAndShadowFailuresExportZeroForEveryEngine(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := obs.New(reg)
	rs := loadRules(t)
	slot := NewSlot(V1(rs), m)
	if got := testutil.CollectAndCount(m.Alerts); got != len(rs.Rules) {
		t.Fatalf("%d alerts series for %d rules and one engine", got, len(rs.Rules))
	}
	if err := slot.StoreWithShadow(V2(rs), V1(rs)); err != nil {
		t.Fatal(err)
	}
	if got := testutil.CollectAndCount(m.Alerts); got != 2*len(rs.Rules) {
		t.Fatalf("%d alerts series for %d rules and two engines", got, len(rs.Rules))
	}
	for _, r := range rs.Rules {
		for _, eng := range []string{"v1", "v2"} {
			if v := testutil.ToFloat64(m.Alerts.WithLabelValues(eng, r.ID)); v != 0 {
				t.Fatalf("alerts{%s, %s} starts at %v", eng, r.ID, v)
			}
		}
	}
	if got := testutil.CollectAndCount(m.ShadowFailures); got != 1 {
		t.Fatalf("%d shadow failures series with v1 shadowing", got)
	}
	if v := testutil.ToFloat64(m.ShadowFailures.WithLabelValues("v1")); v != 0 {
		t.Fatalf("shadow failures{v1} starts at %v", v)
	}

	// A reload that drops a rule drops its alerts series for every engine,
	// as it does for rule_matches_total; a kept rule keeps its count.
	m.Alerts.WithLabelValues("v1", rs.Rules[1].ID).Add(2)
	smaller := *rs
	smaller.Rules = rs.Rules[1:]
	smaller.Version = "smaller"
	if err := slot.StoreWithShadow(V2(&smaller), V1(&smaller)); err != nil {
		t.Fatal(err)
	}
	if got := testutil.CollectAndCount(m.Alerts); got != 2*len(smaller.Rules) {
		t.Fatalf("%d alerts series after dropping a rule, want %d", got, 2*len(smaller.Rules))
	}
	if v := testutil.ToFloat64(m.Alerts.WithLabelValues("v1", rs.Rules[1].ID)); v != 2 {
		t.Fatalf("reload reset a kept rule's alert count to %v", v)
	}
}
