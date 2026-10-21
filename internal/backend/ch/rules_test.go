package ch

import (
	"errors"
	"os"
	"testing"

	"github.com/atontalapur/signalman/internal/sigma"
)

// Every rule the frontend loads, from every rule directory in the tree,
// compiles to a safe, deterministic query or is rejected with a known code.
// Loading a rule is the frontend's acceptance; this is the backend's.
func TestEveryLoadedRuleCompiles(t *testing.T) {
	sets := []struct{ rules, taxonomy string }{
		{"../../sigma/testdata/rules", "../../sigma/testdata/taxonomy"},
		{"../../engine/v1/testdata/rules", "../../engine/v1/testdata/taxonomy"},
		{"../../../rules", "../../../config/taxonomy"},
		{"../../../corpora/sigmahq/rules", "../../../config/taxonomy"},
	}
	known := map[string]bool{CodeTooLarge: true}
	compiled := 0
	for _, s := range sets {
		if _, err := os.Stat(s.rules); err != nil {
			t.Logf("%s: absent, skipped", s.rules)
			continue
		}
		if s.rules == "../../../corpora/sigmahq/rules" && testing.Short() {
			continue
		}
		tax, err := sigma.LoadTaxonomy(s.taxonomy)
		if err != nil {
			t.Fatal(err)
		}
		rs, _, err := sigma.LoadRuleSet(s.rules, tax)
		if err != nil {
			t.Fatal(err)
		}
		rejected := map[string]int{}
		for i := range rs.Rules {
			r := &rs.Rules[i]
			sql, err := CompileRule(r)
			if err != nil {
				var rj *Rejection
				if !errors.As(err, &rj) || !known[rj.Code] || rj.RuleID != r.ID || rj.Reason == "" {
					t.Fatalf("%s: unexpected failure %v", r.Path, err)
				}
				rejected[rj.Code]++
				continue
			}
			assertSafeSQL(t, sql)
			again, err := CompileRule(r)
			if err != nil || again != sql {
				t.Fatalf("%s: compile is not deterministic", r.Path)
			}
			compiled++
		}
		t.Logf("%s: %d rules loaded, %d compiled, rejected by the backend %v",
			s.rules, len(rs.Rules), len(rs.Rules)-sumCounts(rejected), rejected)
	}
	if compiled == 0 {
		t.Fatal("no rule compiled")
	}
}

func sumCounts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
