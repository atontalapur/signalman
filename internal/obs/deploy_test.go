package obs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
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
