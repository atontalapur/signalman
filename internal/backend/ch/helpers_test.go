package ch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atontalapur/signalman/internal/engine/v1"
	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

// testTaxonomy binds product "test" with no match criteria and no renames,
// so a compiled rule is exactly its condition.
func testTaxonomy(t testing.TB) *sigma.Taxonomy {
	t.Helper()
	dir := t.TempDir()
	src := "logsource:\n  product: test\nmatch: {}\nfields: {}\n"
	if err := os.WriteFile(filepath.Join(dir, "test.yml"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	tax, err := sigma.LoadTaxonomy(dir)
	if err != nil {
		t.Fatal(err)
	}
	return tax
}

// loadDetection builds a rule from a detection block written in YAML.
func loadDetection(t testing.TB, tax *sigma.Taxonomy, detection string) *sigma.Rule {
	t.Helper()
	src := "title: t\nid: 00000000-0000-4000-8000-000000000000\nlogsource:\n  product: test\ndetection:\n" + indent(detection)
	r, lerr := sigma.LoadRuleBytes("inline.yml", []byte(src), tax)
	if lerr != nil {
		t.Fatalf("load: %v\n%s", lerr, src)
	}
	return r
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}

// replay is the in-process oracle: v1 over the events, the hits the
// retro-hunt must return, in its order.
func replay(r *sigma.Rule, evs []*event.Event, w Window) []Hit {
	ev1 := v1.New(&sigma.RuleSet{Rules: []sigma.Rule{*r}})
	seen := map[Hit]bool{}
	var out []Hit
	for _, ev := range evs {
		if !w.Contains(ev.EventTime) {
			continue
		}
		for _, vd := range ev1.Evaluate(ev) {
			h := Hit{Partition: vd.Partition, Seq: vd.Seq}
			if vd.Matched && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	sortHits(out)
	return out
}

func sortHits(hs []Hit) {
	for i := 1; i < len(hs); i++ {
		for j := i; j > 0 && less(hs[j], hs[j-1]); j-- {
			hs[j], hs[j-1] = hs[j-1], hs[j]
		}
	}
}

func less(a, b Hit) bool {
	if a.Partition != b.Partition {
		return a.Partition < b.Partition
	}
	return a.Seq < b.Seq
}

func msTime(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

func TestIntegrationDSNFailsUnderCI(t *testing.T) {
	env := func(kv map[string]string) func(string) string {
		return func(k string) string { return kv[k] }
	}
	cases := []struct {
		name     string
		env      map[string]string
		dsn      string
		missing  bool
		mustFail bool
	}{
		{"set", map[string]string{"SIGNALMAN_CLICKHOUSE_DSN": "clickhouse://x"}, "clickhouse://x", false, false},
		{"set under CI", map[string]string{"SIGNALMAN_CLICKHOUSE_DSN": "clickhouse://x", "CI": "true"}, "clickhouse://x", false, false},
		{"unset locally", map[string]string{}, "", true, false},
		{"unset under CI", map[string]string{"CI": "true"}, "", true, true},
	}
	for _, c := range cases {
		dsn, reason, fatal := integrationDSN(env(c.env))
		if dsn != c.dsn || (reason != "") != c.missing || fatal != c.mustFail {
			t.Errorf("%s: got (%q, %q, %v)", c.name, dsn, reason, fatal)
		}
	}
}

// integrationDSN reads the ClickHouse DSN for the integration test. When it
// is missing, reason says so, and fatal is true under CI: a gate that skips
// in CI would read green without running.
func integrationDSN(getenv func(string) string) (dsn, reason string, fatal bool) {
	if dsn = getenv("SIGNALMAN_CLICKHOUSE_DSN"); dsn != "" {
		return dsn, "", false
	}
	return "", "SIGNALMAN_CLICKHOUSE_DSN is not set", getenv("CI") == "true"
}
