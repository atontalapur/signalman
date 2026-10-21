package fixture

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/sigma"
)

func loadRule(t *testing.T) *sigma.Rule {
	t.Helper()
	tax, err := sigma.LoadTaxonomy("../../config/taxonomy")
	if err != nil {
		t.Fatal(err)
	}
	r, lerr := sigma.LoadRule("testdata/proc_dump.yml", tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	return r
}

func TestLoadReadsCasesInOrder(t *testing.T) {
	f, err := Load("testdata/proc_dump.test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if f.Rule != "proc_dump.yml" || len(f.Cases) != 2 {
		t.Fatalf("rule %q, %d cases", f.Rule, len(f.Cases))
	}
	c := f.Cases[0]
	if c.Name != "comsvcs minidump via rundll32" || !c.Expect || c.Line != 3 {
		t.Fatalf("case 0 = %+v", c)
	}
	if got, _ := c.Event.Field("Image").Text(); got != `C:\Windows\System32\rundll32.exe` {
		t.Fatalf("backslashes in a plain YAML scalar are literal, got %q", got)
	}
	if f.Cases[1].Expect {
		t.Fatal("case 1 is no-match")
	}
}

func TestLoadRejectsAuthorErrors(t *testing.T) {
	for file, want := range map[string]string{
		"testdata/bad_expect.test.yml":  `expect must be "match" or "no-match"`,
		"testdata/unknown_key.test.yml": "expected",
		"testdata/no_event.test.yml":    "no event",
		"testdata/missing.test.yml":     "no such file",
		"testdata/two_docs.test.yml":    "one YAML document",
	} {
		_, err := Load(file)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Load(%s) = %v, want an error containing %q", file, err, want)
		}
	}
}

func TestRunPassesAgreeingFixtures(t *testing.T) {
	r := loadRule(t)
	f, err := Load("testdata/proc_dump.test.yml")
	if err != nil {
		t.Fatal(err)
	}
	res := Run(r, f)
	if !res.OK() {
		t.Fatalf("expected a pass, got %+v", res)
	}
	if res.Matches != 1 || res.NoMatches != 1 {
		t.Fatalf("counts = %d/%d", res.Matches, res.NoMatches)
	}
}

func TestRunReportsEachDisagreement(t *testing.T) {
	r := loadRule(t)
	f, err := Load("testdata/wrong.test.yml")
	if err != nil {
		t.Fatal(err)
	}
	res := Run(r, f)
	if res.OK() {
		t.Fatal("a disagreeing case must fail the rule")
	}
	if len(res.Failed) != 1 || res.Failed[0].Case.Name != "claims a match that is not one" || res.Failed[0].Got {
		t.Fatalf("failed = %+v", res.Failed)
	}
}

func TestRunNeedsBothAMatchAndANoMatchCase(t *testing.T) {
	r := loadRule(t)
	f, err := Load("testdata/one_sided.test.yml")
	if err != nil {
		t.Fatal(err)
	}
	res := Run(r, f)
	if len(res.Failed) != 0 {
		t.Fatalf("the one case agrees: %+v", res.Failed)
	}
	if res.OK() {
		t.Fatal("a rule with no no-match case must fail")
	}
	if !strings.Contains(res.Problem, "no-match") {
		t.Fatalf("problem = %q", res.Problem)
	}
}

func TestRunChecksTheRuleNameAgainstTheFile(t *testing.T) {
	r := loadRule(t)
	f, err := Load("testdata/proc_dump.test.yml")
	if err != nil {
		t.Fatal(err)
	}
	f.Rule = "other.yml"
	if res := Run(r, f); res.OK() || !strings.Contains(res.Problem, "other.yml") {
		t.Fatalf("a fixture naming another rule must fail, got %+v", res)
	}
}
