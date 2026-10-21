package obs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

const deployDir = "../../deploy"

var metricRef = regexp.MustCompile(`signalman_[a-z_]+`)

// baseName strips the series suffixes a histogram exports under.
func baseName(s string) string {
	for _, suf := range []string{"_bucket", "_sum", "_count"} {
		if strings.HasSuffix(s, suf) && strings.HasSuffix(strings.TrimSuffix(s, suf), "_seconds") {
			return strings.TrimSuffix(s, suf)
		}
	}
	return s
}

func registeredNames(t *testing.T) map[string]bool {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := New(reg)
	touch(m)
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, f := range fams {
		out[f.GetName()] = true
	}
	return out
}

// The dashboard and the alert rules name metrics by string. A rename in
// code that misses them leaves a blank panel or an alert that can never
// fire, and nothing errors.
func TestDeployFilesReferenceOnlyRegisteredMetrics(t *testing.T) {
	names := registeredNames(t)
	files, err := filepath.Glob(filepath.Join(deployDir, "prometheus", "alerts", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no alert files: %v", err)
	}
	files = append(files, filepath.Join(deployDir, "grafana", "dashboards", "signalman.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range metricRef.FindAllString(string(b), -1) {
			if !names[baseName(ref)] {
				t.Errorf("%s names %s, which is not registered", f, ref)
			}
		}
	}
}

func TestDashboardShowsEveryCoreMetric(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(deployDir, "grafana", "dashboards", "signalman.json"))
	if err != nil {
		t.Fatal(err)
	}
	var dash struct {
		UID    string `json:"uid"`
		Panels []struct {
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(b, &dash); err != nil {
		t.Fatalf("dashboard JSON: %v", err)
	}
	if dash.UID == "" {
		t.Fatal("dashboard has no uid; provisioning would duplicate it on every restart")
	}
	shown := map[string]bool{}
	for _, p := range dash.Panels {
		for _, tg := range p.Targets {
			for _, ref := range metricRef.FindAllString(tg.Expr, -1) {
				shown[baseName(ref)] = true
			}
		}
	}
	for name := range coreMetricsTable(t) {
		if !shown[name] {
			t.Errorf("no dashboard panel queries %s", name)
		}
	}
}

// Each binary serves its own /metrics: signalmand on :9464, signalman-sink
// on :9465 (their -metrics-addr defaults). A process Prometheus does not
// scrape has no alerts at all, and its absent() rule fires forever, which
// reads as a page about the process, not the config.
func TestPrometheusScrapesEveryBinary(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(deployDir, "prometheus", "prometheus.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		ScrapeConfigs []struct {
			StaticConfigs []struct {
				Targets []string `yaml:"targets"`
			} `yaml:"static_configs"`
		} `yaml:"scrape_configs"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	scraped := map[string]bool{}
	for _, sc := range cfg.ScrapeConfigs {
		for _, st := range sc.StaticConfigs {
			for _, tg := range st.Targets {
				if i := strings.LastIndex(tg, ":"); i >= 0 {
					scraped[tg[i:]] = true
				}
			}
		}
	}
	for port, bin := range map[string]string{":9464": "signalmand", ":9465": "signalman-sink"} {
		if !scraped[port] {
			t.Errorf("prometheus.yml scrapes nothing on %s, where %s serves /metrics", port, bin)
		}
	}
}

// SignalmanSinkCanaryStalled reads the same canary at the table. Its page
// budget is argued once, on SignalmanCanaryStalled, and checked by
// internal/pipe TestCanaryStallPagesWithinTwoMinutes; it holds for the sink
// rule only while the threshold, for and severity match.
func TestSinkCanaryRuleMirrorsThePipelineRule(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(deployDir, "prometheus", "alerts", "absence.yml"))
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
	type rule struct{ expr, hold, sev string }
	got := map[string]rule{}
	for _, g := range f.Groups {
		for _, r := range g.Rules {
			got[r.Alert] = rule{r.Expr, r.For, r.Labels["severity"]}
		}
	}
	pipe, sink := got["SignalmanCanaryStalled"], got["SignalmanSinkCanaryStalled"]
	if want := strings.Replace(pipe.expr, "signalman_canary_age_seconds", "signalman_sink_canary_age_seconds", 1); sink.expr != want ||
		sink.hold != pipe.hold || sink.sev != pipe.sev || pipe.expr == "" {
		t.Errorf("SignalmanSinkCanaryStalled %+v does not mirror SignalmanCanaryStalled %+v", sink, pipe)
	}
	if a := got["SignalmanSinkCanaryAbsent"]; a.expr != "absent(signalman_sink_canary_age_seconds)" || a.sev != "page" {
		t.Errorf("SignalmanSinkCanaryAbsent is %+v; want a page on absent(signalman_sink_canary_age_seconds)", a)
	}
}
