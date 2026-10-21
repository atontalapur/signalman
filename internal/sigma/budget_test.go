package sigma

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const budgetRule = `title: t
id: 0b0d0e0a-0000-4000-8000-000000000001
level: low
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\x.exe'
  condition: selection
`

func TestLoadRuleReadsBudget(t *testing.T) {
	tax := loadTax(t)
	for src, want := range map[string]float64{
		"budget: 5\n":   5,
		"budget: 0.5\n": 0.5,
		"budget: 0\n":   0,
	} {
		r, lerr := LoadRuleBytes("b.yml", []byte(budgetRule+src), tax)
		if lerr != nil {
			t.Fatalf("%q: %v", src, lerr)
		}
		if r.Budget == nil || *r.Budget != want {
			t.Fatalf("%q: budget = %v, want %v", src, r.Budget, want)
		}
	}
}

func TestLoadRuleWithoutBudgetHasNone(t *testing.T) {
	r, lerr := LoadRuleBytes("b.yml", []byte(budgetRule), loadTax(t))
	if lerr != nil {
		t.Fatal(lerr)
	}
	if r.Budget != nil {
		t.Fatalf("budget = %v", *r.Budget)
	}
}

func TestLoadRuleRejectsABadBudget(t *testing.T) {
	tax := loadTax(t)
	for _, src := range []string{"budget: -1\n", "budget: lots\n", "budget: [1]\n", "budget: .nan\n", "budget: .inf\n"} {
		_, lerr := LoadRuleBytes("b.yml", []byte(budgetRule+src), tax)
		if lerr == nil {
			t.Fatalf("%q should be rejected", src)
		}
		if lerr.Code != CodeYAML || lerr.Line != 11 || !strings.Contains(lerr.Reason, "budget") {
			t.Fatalf("%q: %+v", src, lerr)
		}
	}
}

// A budget is about noise, not about what the rule matches, so it must not
// move RuleSetV: tuning a budget is not a semantic change to the rule set.
func TestBudgetDoesNotMoveRuleSetVersion(t *testing.T) {
	tax := loadTax(t)
	versions := map[string]string{}
	for name, src := range map[string]string{"none": budgetRule, "three": budgetRule + "budget: 3\n"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "b.yml"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		rs, errs, err := LoadRuleSet(dir, tax)
		if err != nil || len(errs) != 0 || len(rs.Rules) != 1 {
			t.Fatalf("%s: %v %v", name, err, errs)
		}
		versions[name] = rs.Version
	}
	if versions["none"] != versions["three"] {
		t.Fatal("a budget changed RuleSetV")
	}
}
