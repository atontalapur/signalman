package pipe

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/broker"
	"github.com/atontalapur/signalman/internal/sigma"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"gopkg.in/yaml.v3"
)

const (
	shippedRules = "../../rules"
	alertsDir    = "../../deploy/prometheus"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func loadShippedRules(t testing.TB) *sigma.RuleSet {
	t.Helper()
	rs, errs, err := sigma.LoadRuleSet(shippedRules, loadTaxonomy(t))
	if err != nil || len(errs) != 0 {
		t.Fatal(err, errs)
	}
	return rs
}

func TestCanaryRuleIsTheShippedRule(t *testing.T) {
	r, lerr := sigma.LoadRule(shippedRules+"/signalman_canary.yml", loadTaxonomy(t))
	if lerr != nil {
		t.Fatal(lerr)
	}
	if r.ID != CanaryRuleID {
		t.Fatalf("rules/signalman_canary.yml has id %s, CanaryRuleID is %s", r.ID, CanaryRuleID)
	}
}

// The canary event goes through the normalizer and the engine like any
// event, and matches the canary rule and nothing else in the shipped set.
func TestCanaryRecordMatchesOnlyTheCanaryRule(t *testing.T) {
	rs := loadShippedRules(t)
	r := newRig(t, nil, nil)
	for p := int32(0); p < 3; p++ {
		rec := CanaryRecord(p, time.Unix(1790000000, 0))
		rec.Offset = 7
		if rec.Partition != p || rec.Topic != TopicEventsRaw {
			t.Fatalf("record %+v is not pinned to events.raw/%d", rec, p)
		}
		it := NewIngest(r.m).Admit(rec)
		r.norm.Normalize(it)
		if it.Drop != nil {
			t.Fatalf("canary dropped: %+v", it.Drop)
		}
		if !it.Event.EventTime.Equal(time.Unix(1790000000, 0)) {
			t.Fatalf("event time %v", it.Event.EventTime)
		}
		for _, v := range V1(rs).EvaluateInto(nil, it.Event) {
			if v.Matched != (v.RuleID == CanaryRuleID) {
				t.Fatalf("rule %s matched=%v on the canary event", v.RuleID, v.Matched)
			}
		}
	}
}

// stalledRule is SignalmanCanaryStalled as written in absence.yml.
type stalledRule struct {
	threshold float64
	hold      time.Duration
}

func readStalledRule(t *testing.T) (stalledRule, time.Duration) {
	t.Helper()
	b, err := os.ReadFile(alertsDir + "/alerts/absence.yml")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Groups []struct {
			Rules []struct {
				Alert  string            `yaml:"alert"`
				Expr   string            `yaml:"expr"`
				For    string            `yaml:"for"`
				Labels map[string]string `yaml:"labels"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	var sr stalledRule
	found := false
	for _, g := range f.Groups {
		for _, r := range g.Rules {
			if r.Alert != "SignalmanCanaryStalled" {
				continue
			}
			m := regexp.MustCompile(`^signalman_canary_age_seconds > ([0-9]+)$`).FindStringSubmatch(r.Expr)
			if m == nil {
				t.Fatalf("SignalmanCanaryStalled expr %q is not the shape this test models", r.Expr)
			}
			sr.threshold, _ = strconv.ParseFloat(m[1], 64)
			if sr.hold, err = time.ParseDuration(r.For); err != nil {
				t.Fatal(err)
			}
			if r.Labels["severity"] != "page" {
				t.Fatalf("SignalmanCanaryStalled severity %q, want page", r.Labels["severity"])
			}
			found = true
		}
	}
	if !found {
		t.Fatal("absence.yml has no SignalmanCanaryStalled")
	}

	b, err = os.ReadFile(alertsDir + "/prometheus.yml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Global struct {
			Scrape string `yaml:"scrape_interval"`
			Eval   string `yaml:"evaluation_interval"`
		} `yaml:"global"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	scrape, err1 := time.ParseDuration(cfg.Global.Scrape)
	eval, err2 := time.ParseDuration(cfg.Global.Eval)
	if err := errors.Join(err1, err2); err != nil {
		t.Fatal(err)
	}
	if scrape != eval {
		t.Fatalf("model assumes scrape (%v) and evaluation (%v) intervals are equal", scrape, eval)
	}
	return sr, scrape
}

// alertModel evaluates SignalmanCanaryStalled per partition the way
// Prometheus does: on each evaluation, a series over the threshold is
// pending, and fires once it has been pending for the rule's for.
type alertModel struct {
	rule    stalledRule
	pending map[int32]time.Time
	fired   map[int32]time.Time
}

func (a *alertModel) eval(now time.Time, ages map[int32]float64) {
	for p, age := range ages {
		if age <= a.rule.threshold {
			delete(a.pending, p)
			continue
		}
		since, ok := a.pending[p]
		if !ok {
			a.pending[p] = now
			since = now
		}
		if _, done := a.fired[p]; !done && now.Sub(since) >= a.rule.hold {
			a.fired[p] = now
		}
	}
}

func waitCommitted(t *testing.T, b broker.Broker, errc <-chan error) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		done, err := committedAll(b)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			return
		}
		select {
		case err := <-errc:
			t.Fatalf("pipeline stopped: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for commits")
		case <-time.After(time.Millisecond):
		}
	}
}

// The S-51 acceptance: kill the consumer and SignalmanCanaryStalled fires
// on every partition within two minutes. Time is a fake clock stepped one
// scrape interval at a time; the pipeline and the canary are real, over
// the in-memory broker.
func TestCanaryStallPagesWithinTwoMinutes(t *testing.T) {
	rule, step := readStalledRule(t)
	// The worst case adds a scrape and an evaluation interval to the
	// threshold and the for: see the comment in absence.yml.
	if worst := time.Duration(rule.threshold)*time.Second + 2*step + rule.hold; worst > 2*time.Minute {
		t.Fatalf("worst-case page delay %v is over two minutes", worst)
	}
	const interval = 30 * time.Second
	if rule.threshold <= interval.Seconds() {
		t.Fatalf("threshold %vs is inside the %v canary interval; a healthy pipeline would page", rule.threshold, interval)
	}

	clk := &fakeClock{t: time.Unix(1790000000, 0)}
	mem := newMemory()
	r := newRigClock(t, mem, mem, clk.Now)
	r.rs = loadShippedRules(t)
	canary := NewCanary(mem, r.m, clk.Now, nil)

	ctx, kill := context.WithCancel(context.Background())
	defer kill()
	errc := make(chan error, 1)
	go func() { errc <- newPipeline(t, r, testConfig()).Run(ctx) }()

	model := &alertModel{rule: rule, pending: map[int32]time.Time{}, fired: map[int32]time.Time{}}
	ages := func() map[int32]float64 {
		out := map[int32]float64{}
		for p := int32(0); p < testPartitions; p++ {
			a, ok := r.m.CanaryAge.Age(p)
			if !ok {
				t.Fatalf("partition %d has no canary age", p)
			}
			out[p] = a.Seconds()
		}
		return out
	}
	tick := func(alive bool) {
		if clk.Now().Sub(time.Unix(1790000000, 0))%interval == 0 {
			if err := canary.Inject(context.Background()); err != nil {
				t.Fatal(err)
			}
			if alive {
				waitCommitted(t, mem, errc)
				// The canary alert reached the sink: every age is zero.
				for p, a := range ages() {
					if a != 0 {
						t.Fatalf("partition %d canary age %vs right after its alert was durable", p, a)
					}
				}
			}
		}
		model.eval(clk.Now(), ages())
		clk.Add(step)
	}

	// Healthy for five minutes: no page, ages never past the interval.
	for clk.Now().Before(time.Unix(1790000000, 0).Add(5 * time.Minute)) {
		tick(true)
		for p, a := range ages() {
			if a > interval.Seconds() {
				t.Fatalf("healthy partition %d canary age %vs", p, a)
			}
		}
	}
	if len(model.fired) != 0 || len(model.pending) != 0 {
		t.Fatalf("healthy pipeline paged: fired %v pending %v", model.fired, model.pending)
	}
	if testutil.ToFloat64(r.m.CanaryInjected.WithLabelValues("0")) != 10 {
		t.Fatalf("partition 0 injected %v canaries in 5m, want 10", testutil.ToFloat64(r.m.CanaryInjected.WithLabelValues("0")))
	}
	// Canary traffic alone must not look like fresh upstream data.
	for p := int32(0); p < testPartitions; p++ {
		if _, ok := r.m.Staleness.Age(p); ok {
			t.Fatalf("partition %d has staleness from canary events alone", p)
		}
	}

	// Kill the consumer. The generator keeps injecting; nothing consumes.
	kill()
	if err := <-errc; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	killedAt := clk.Now()
	for clk.Now().Sub(killedAt) <= 2*time.Minute {
		tick(false)
	}
	for p := int32(0); p < testPartitions; p++ {
		at, ok := model.fired[p]
		if !ok {
			t.Fatalf("partition %d: SignalmanCanaryStalled did not fire within 2m of the kill (age %v)", p, ages()[p])
		}
		if d := at.Sub(killedAt); d > 2*time.Minute {
			t.Fatalf("partition %d paged %v after the kill", p, d)
		}
	}
	for p, a := range ages() {
		if a <= rule.threshold {
			t.Fatalf("partition %d age %vs after 2m dead, not over the %vs threshold", p, a, rule.threshold)
		}
	}
}

// A consumer that never came up still pages: the generator starts every
// partition's age when it first injects there.
func TestCanaryAgeClimbsWhenNothingEverConsumes(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1790000000, 0)}
	mem := newMemory()
	r := newRigClock(t, mem, mem, clk.Now)
	canary := NewCanary(mem, r.m, clk.Now, nil)
	if err := canary.Inject(context.Background()); err != nil {
		t.Fatal(err)
	}
	clk.Add(90 * time.Second)
	for p := int32(0); p < testPartitions; p++ {
		if a, ok := r.m.CanaryAge.Age(p); !ok || a != 90*time.Second {
			t.Fatalf("partition %d age %v tracked %v, want 90s", p, a, ok)
		}
	}
	end, err := mem.EndOffsets(context.Background(), TopicEventsRaw)
	if err != nil {
		t.Fatal(err)
	}
	for p, e := range end {
		if e != 1 {
			t.Fatalf("partition %d holds %d records after one injection, want 1", p, e)
		}
	}
}

// partitionDown is a broker whose events.raw partition down has no leader:
// listing offsets fails for the whole topic, as kadm reports one shard
// error, and any produce holding a record for it fails.
type partitionDown struct {
	*broker.Memory
	down int32
}

var errNoLeader = errors.New("NOT_LEADER_FOR_PARTITION")

func (b *partitionDown) EndOffsets(ctx context.Context, topic string) (map[int32]int64, error) {
	if topic == TopicEventsRaw && b.down >= 0 {
		return nil, errNoLeader
	}
	return b.Memory.EndOffsets(ctx, topic)
}

func (b *partitionDown) Produce(ctx context.Context, recs []broker.Record) error {
	for _, r := range recs {
		if r.Topic == TopicEventsRaw && r.Partition == b.down {
			return errNoLeader
		}
	}
	return b.Memory.Produce(ctx, recs)
}

// One partition losing its leader must not stop the canary on the others:
// on Redpanda (docs/load.md, "One partition offline") a single broker down
// paged SignalmanCanaryStalled for all eight partitions, which hides which
// one is actually out.
func TestCanaryKeepsTheOtherPartitionsWhenOneIsDown(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1790000000, 0)}
	mem := newMemory()
	r := newRigClock(t, mem, mem, clk.Now)
	b := &partitionDown{Memory: mem, down: -1}
	canary := NewCanary(b, r.m, clk.Now, nil)
	if err := canary.Inject(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.down = 2
	if err := canary.Inject(context.Background()); err == nil {
		t.Fatal("an injection with partition 2 down reported no error")
	}
	end, err := mem.EndOffsets(context.Background(), TopicEventsRaw)
	if err != nil {
		t.Fatal(err)
	}
	for p, e := range end {
		want := int64(2)
		if p == 2 {
			want = 1
		}
		if e != want {
			t.Errorf("partition %d holds %d canaries after two injections, want %d", p, e, want)
		}
	}
}
