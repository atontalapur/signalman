package loadtest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/sigma"
)

// The load runs are long and machine-dependent, so they run only when
// asked for:
//
//	SIGNALMAN_LOAD=1 go test -run TestLoadBaseline -v -timeout 1h ./internal/loadtest/
//
// SIGNALMAN_CORPUS points at the SigmaHQ clone (default corpora/sigmahq at
// the module root); without it the twenty rules in rules/ are used, which
// is a far lighter rule set and says little about the spec's targets.
// SIGNALMAN_LOAD_OUT names a directory for one JSON report per run.
// SIGNALMAN_LOAD_SCALE multiplies every phase duration (default 1).

func requireLoad(t *testing.T) {
	t.Helper()
	if os.Getenv("SIGNALMAN_LOAD") == "" {
		t.Skip("load run; set SIGNALMAN_LOAD=1")
	}
}

// loadRuleSet is the rule set and taxonomy a load run evaluates, and its
// name for the report.
type loadRuleSet struct {
	name string
	rs   *sigma.RuleSet
	tax  *sigma.Taxonomy
}

func loadRules(t *testing.T) loadRuleSet {
	t.Helper()
	tax, err := sigma.LoadTaxonomy(repoTaxonomy)
	if err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("SIGNALMAN_CORPUS")
	if root == "" {
		root = "../../corpora/sigmahq"
	}
	dir := filepath.Join(root, "rules")
	if _, err := os.Stat(dir); err == nil {
		rs, _, err := sigma.LoadRuleSet(dir, tax)
		if err != nil {
			t.Fatal(err)
		}
		return loadRuleSet{name: "sigmahq-rules", rs: rs, tax: tax}
	}
	rs, _ := repoSet(t)
	return loadRuleSet{name: "repo-rules", rs: rs, tax: tax}
}

func scaled(d time.Duration) time.Duration {
	if s := os.Getenv("SIGNALMAN_LOAD_SCALE"); s != "" {
		x, err := strconv.ParseFloat(s, 64)
		if err == nil && x > 0 {
			return time.Duration(float64(d) * x)
		}
	}
	return d
}

// envInt reads a positive integer override.
func envInt(name string, def int) int {
	if s := os.Getenv(name); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// envFloat reads a positive float override.
func envFloat(name string, def float64) float64 {
	if s := os.Getenv(name); s != "" {
		if x, err := strconv.ParseFloat(s, 64); err == nil && x > 0 {
			return x
		}
	}
	return def
}

// Environment is stamped on every report: every number here is in
// process, over the in-memory broker, on whatever machine ran it.
type Environment struct {
	Label      string `json:"label"`
	GoVersion  string `json:"go"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	NumCPU     int    `json:"num_cpu"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	RuleSet    string `json:"rule_set"`
	Rules      int    `json:"rules"`
	Date       string `json:"date"`
}

func environment(set loadRuleSet) Environment {
	return Environment{
		Label:      "in-process, in-memory broker",
		GoVersion:  runtime.Version(),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
		RuleSet:    set.name,
		Rules:      len(set.rs.Rules),
		Date:       time.Now().UTC().Format(time.DateOnly),
	}
}

func writeReport(t *testing.T, name string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s report:\n%s", name, b)
	if dir := os.Getenv("SIGNALMAN_LOAD_OUT"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// loadCorpus is the generated corpus for a load run: AimedFields over the
// rule set, drop-free.
func loadCorpus(t *testing.T, set loadRuleSet) *Corpus {
	t.Helper()
	c, err := FromRules(set.rs, set.tax, envInt("SIGNALMAN_LOAD_PER_RULE", 20), 1)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func loadConfig(set loadRuleSet) Config {
	return Config{Rules: set.rs, Taxonomy: set.tax}
}

// BaselineReport is S-60's measurement.
type BaselineReport struct {
	Env      Environment     `json:"env"`
	Pipe     string          `json:"pipe"`
	Corpus   int             `json:"corpus_records"`
	Capacity Capacity        `json:"capacity"`
	Latency  []LatencyAtLoad `json:"latency"`
}

// LatencyAtLoad is end-to-end latency with the pipeline offered a fixed
// fraction of its measured capacity.
type LatencyAtLoad struct {
	Fraction  float64     `json:"fraction"`
	Rate      float64     `json:"rate"`
	For       string      `json:"for"`
	Sent      int         `json:"sent"`
	Latency   Latency     `json:"latency"`
	Correct   bool        `json:"correct"`
	Resources Resources   `json:"resources"`
	Replay    ReplayStats `json:"replay"`
}

func pipeString(c Config) string {
	c = c.withDefaults()
	p := c.Pipe
	return fmt.Sprintf("partitions=%d max-poll=%d normalize-workers=%d match-workers=%d queue=%d inflight=%d",
		c.Partitions, c.MaxPoll, p.NormalizeWorkers, p.MatchWorkers, p.QueueSize, p.MaxInflightBatches)
}

// measureBaseline is the capacity of the pipeline on this rule set, used as
// 1x by every experiment. SIGNALMAN_LOAD_BASELINE skips the measurement and
// uses the given rate.
func measureBaseline(t *testing.T, set loadRuleSet, c *Corpus) Capacity {
	t.Helper()
	if r := envFloat("SIGNALMAN_LOAD_BASELINE", 0); r > 0 {
		return Capacity{Rate: r, Rules: len(set.rs.Rules)}
	}
	n := envInt("SIGNALMAN_LOAD_CAPACITY_EVENTS", 0)
	if n == 0 {
		// About 15 seconds of work at either rule set's speed.
		n = 40000
		if len(set.rs.Rules) < 100 {
			n = 1000000
		}
	}
	capy, err := MeasureCapacity(context.Background(), loadConfig(set), c, n, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return capy
}

func TestLoadBaseline(t *testing.T) {
	requireLoad(t)
	set := loadRules(t)
	c := loadCorpus(t, set)
	capy := measureBaseline(t, set, c)
	rep := BaselineReport{Env: environment(set), Pipe: pipeString(loadConfig(set)), Corpus: len(c.Records), Capacity: capy}
	for _, frac := range []float64{0.5, 0.8} {
		h, err := New(loadConfig(set))
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Start(); err != nil {
			t.Fatal(err)
		}
		dur := scaled(30 * time.Second)
		ph := Phase{Rate: frac * capy.Rate, For: dur}
		st, err := h.Replay(context.Background(), c, ReplayConfig{Phases: []Phase{ph}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.WaitCommitted(context.Background(), 10*time.Minute); err != nil {
			t.Fatal(err)
		}
		ck := h.Check()
		// The first five seconds are warm-up: the first polls, the first GC.
		lat := Summarize(h.Tap.Latencies(), 5*time.Second, 0)
		rep.Latency = append(rep.Latency, LatencyAtLoad{
			Fraction: frac, Rate: ph.Rate, For: dur.String(), Sent: st.Sent,
			Latency: lat, Correct: ck.OK() && ck.Dropped == 0 && ck.Evaluated == st.Sent,
			Resources: ResourcesOf(h.Samples()), Replay: st,
		})
		h.Close()
		if !ck.OK() {
			t.Fatalf("baseline run at %.1fx failed its accounting: %+v", frac, ck)
		}
	}
	writeReport(t, "baseline-"+set.name, rep)
}
