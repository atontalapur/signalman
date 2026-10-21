package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copyRule copies the shipped proc_dump rule and its fixture into a temp
// dir, with extra lines appended to the rule, and returns the rule path.
func copyRule(t *testing.T, name, extra string) string {
	t.Helper()
	dir := t.TempDir()
	src, err := os.ReadFile("../../rules/proc_dump.yml")
	if err != nil {
		t.Fatal(err)
	}
	fix, err := os.ReadFile("../../rules/proc_dump.test.yml")
	if err != nil {
		t.Fatal(err)
	}
	fix = []byte(strings.Replace(string(fix), "rule: proc_dump.yml", "rule: "+name+".yml", 1))
	p := filepath.Join(dir, name+".yml")
	if err := os.WriteFile(p, append(src, []byte(extra)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".test.yml"), fix, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// gates runs the gates command with a generous latency budget, so only the
// test that wants a latency failure gets one.
func gates(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	base := []string{"gates", "--taxonomy", testTaxonomy, "--samples", "50", "--threshold", "1h"}
	return cli(t, append(base, args...)...)
}

// row returns the report's table row for the rule at path.
func row(t *testing.T, report, path string) string {
	t.Helper()
	for _, l := range strings.Split(report, "\n") {
		if strings.HasPrefix(l, "| `"+path+"` |") {
			return l
		}
	}
	t.Fatalf("no row for %s in:\n%s", path, report)
	return ""
}

// cell returns gate i's cell (0 parse ... 4 prefilter) from a table row.
func cell(t *testing.T, r string, i int) string {
	t.Helper()
	parts := strings.Split(r, " | ")
	if len(parts) != numGates+1 {
		t.Fatalf("row has %d cells: %s", len(parts), r)
	}
	return strings.TrimSuffix(parts[i+1], " |")
}

func TestGatesPassAShippedRule(t *testing.T) {
	code, out, stderr := gates(t, "../../rules/proc_dump.yml")
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, out, stderr)
	}
	if !strings.HasPrefix(out, reportMarker+"\n") {
		t.Fatalf("report must start with the comment marker:\n%s", out)
	}
	for _, want := range []string{
		"| Rule | Parse | Fixtures | Noise | Latency | Prefilter |",
		"1 rule checked: 0 failed, 0 with warnings, 1 passed.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	r := row(t, out, "../../rules/proc_dump.yml")
	for i, want := range []string{"pass", "pass, 3 cases", "skipped", "pass, p99 ", "pass"} {
		if c := cell(t, r, i); !strings.HasPrefix(c, want) {
			t.Errorf("gate %s cell %q, want prefix %q", gateNames[i], c, want)
		}
	}
	if !strings.Contains(out, "no corpus given") {
		t.Errorf("a skipped noise gate states why:\n%s", out)
	}
}

func TestGatesParseFailureSkipsTheRest(t *testing.T) {
	code, out, _ := gates(t, "../../internal/sigma/testdata/rules_bad/no_id.yml")
	if code != exitFail {
		t.Fatalf("code %d\n%s", code, out)
	}
	r := row(t, out, "../../internal/sigma/testdata/rules_bad/no_id.yml")
	if c := cell(t, r, gParse); !strings.HasPrefix(c, "**FAIL**") {
		t.Errorf("parse cell %q", c)
	}
	for i := gFixtures; i < numGates; i++ {
		if c := cell(t, r, i); c != "skipped" {
			t.Errorf("gate %s cell %q, want skipped", gateNames[i], c)
		}
	}
	if !strings.Contains(out, "[missing-id]") {
		t.Errorf("the load error is in the details:\n%s", out)
	}
}

func TestGatesFixtureDisagreementFails(t *testing.T) {
	code, out, _ := gates(t, "testdata/fail/proc_dump.yml")
	if code != exitFail {
		t.Fatalf("code %d\n%s", code, out)
	}
	if c := cell(t, row(t, out, "testdata/fail/proc_dump.yml"), gFixtures); !strings.HasPrefix(c, "**FAIL**") {
		t.Errorf("fixtures cell %q", c)
	}
	if !strings.Contains(out, `case "claims a match that is not one" (line 3): want match, got no-match`) {
		t.Errorf("the failing case is in the details:\n%s", out)
	}
}

func TestGatesNoiseWithoutBudgetPasses(t *testing.T) {
	code, out, _ := gates(t, "--corpus", "testdata/corpus", "../../rules/proc_dump.yml")
	if code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	c := cell(t, row(t, out, "../../rules/proc_dump.yml"), gNoise)
	if c != "pass, 33333.3 per 100k, no budget" {
		t.Errorf("noise cell %q", c)
	}
	// The figure comes with its sample matches.
	if !strings.Contains(out, filepath.Join("testdata/corpus", "a.ndjson")+":1") {
		t.Errorf("samples missing:\n%s", out)
	}
}

func TestGatesNoiseWithinBudgetPasses(t *testing.T) {
	p := copyRule(t, "proc_dump", "budget: 40000\n")
	code, out, _ := gates(t, "--corpus", "testdata/corpus", p)
	if code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
	if c := cell(t, row(t, out, p), gNoise); c != "pass, 33333.3 per 100k, budget 40000" {
		t.Errorf("noise cell %q", c)
	}
}

func TestGatesNoiseOverBudgetFails(t *testing.T) {
	p := copyRule(t, "proc_dump", "budget: 5\n")
	code, out, _ := gates(t, "--corpus", "testdata/corpus", p)
	if code != exitFail {
		t.Fatalf("code %d\n%s", code, out)
	}
	if c := cell(t, row(t, out, p), gNoise); c != "**FAIL** 33333.3 per 100k, budget 5" {
		t.Errorf("noise cell %q", c)
	}
	if !strings.Contains(out, "2 matches in 6 events") {
		t.Errorf("details lack the counts:\n%s", out)
	}
}

func TestGatesLatencyOverBudgetFails(t *testing.T) {
	code, out, _ := cli(t, "gates", "--taxonomy", testTaxonomy, "--samples", "50", "--threshold", "1ns",
		"../../rules/proc_dump.yml")
	if code != exitFail {
		t.Fatalf("code %d\n%s", code, out)
	}
	if c := cell(t, row(t, out, "../../rules/proc_dump.yml"), gLatency); !strings.HasPrefix(c, "**FAIL** p99 ") {
		t.Errorf("latency cell %q", c)
	}
	if !strings.Contains(out, "over the 1ns p99 budget") {
		t.Errorf("details lack the budget:\n%s", out)
	}
}

// The spec makes Always membership a warning: the rule still merges, but
// its author is told every event will walk its tree.
func TestGatesAlwaysIsAWarningNotAFailure(t *testing.T) {
	code, out, stderr := cli(t, "gates", "--taxonomy", "testdata/gates/taxonomy", "--samples", "50",
		"--threshold", "1h", "testdata/gates/always")
	if code != exitOK {
		t.Fatalf("a warning must not fail the gates: code %d\n%s%s", code, out, stderr)
	}
	r := row(t, out, "testdata/gates/always/regex_only.yml")
	if c := cell(t, r, gPrefilter); c != "warning, in Always" {
		t.Errorf("prefilter cell %q", c)
	}
	if c := cell(t, r, gFixtures); c != "pass, 2 cases" {
		t.Errorf("fixtures cell %q", c)
	}
	if !strings.Contains(out, "1 rule checked: 0 failed, 1 with warnings, 0 passed.") {
		t.Errorf("summary:\n%s", out)
	}
	if !strings.Contains(out, "docs/authoring.md") {
		t.Errorf("the warning points at the guide:\n%s", out)
	}
}

func TestGatesDuplicateIDAgainstTheRuleSetFails(t *testing.T) {
	// A copy of an existing rule under a new name keeps its id.
	p := copyRule(t, "aaa_copy", "")
	code, out, _ := gates(t, "--set", "../../rules", p)
	if code != exitFail {
		t.Fatalf("code %d\n%s", code, out)
	}
	if c := cell(t, row(t, out, p), gParse); !strings.HasPrefix(c, "**FAIL**") {
		t.Errorf("parse cell %q", c)
	}
	if !strings.Contains(out, "[duplicate-id]") || !strings.Contains(out, filepath.Join("../../rules", "proc_dump.yml")) {
		t.Errorf("details name the other file:\n%s", out)
	}
	// The rule itself is part of --set and is not its own duplicate.
	code, out, _ = gates(t, "--set", "../../rules", "../../rules/proc_dump.yml")
	if code != exitOK {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestGatesDuplicateIDInAnotherCaseFails(t *testing.T) {
	// The same id in upper case is the same UUID, so it is still a duplicate.
	p := copyRule(t, "aaa_upper", "")
	src, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	const id = "47c606a8-cce7-4720-aafa-90c8e2a0f166"
	if !strings.Contains(string(src), id) {
		t.Fatalf("proc_dump.yml no longer has id %s", id)
	}
	upper := strings.Replace(string(src), id, strings.ToUpper(id), 1)
	if err := os.WriteFile(p, []byte(upper), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := gates(t, "--set", "../../rules", p)
	if code != exitFail {
		t.Fatalf("code %d\n%s", code, out)
	}
	if c := cell(t, row(t, out, p), gParse); !strings.HasPrefix(c, "**FAIL**") {
		t.Errorf("parse cell %q", c)
	}
	if !strings.Contains(out, "[duplicate-id] rule "+id) {
		t.Errorf("details name the lower-case id:\n%s", out)
	}
}

func TestGatesChangedListMapsFixturesToRules(t *testing.T) {
	list := filepath.Join(t.TempDir(), "changed")
	// NUL separated, as git diff -z writes it, with a fixture, a duplicate,
	// a deleted rule, and a file that is not a rule.
	names := "../../rules/proc_dump.test.yml\x00../../rules/proc_dump.yml\x00../../rules/gone.yml\x00../../rules/README.md\x00"
	if err := os.WriteFile(list, []byte(names), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := gates(t, "--changed", list)
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, out, stderr)
	}
	row(t, out, "../../rules/proc_dump.yml")
	if !strings.Contains(out, "1 rule checked") {
		t.Errorf("one rule, once:\n%s", out)
	}
	if !strings.Contains(out, "`../../rules/gone.yml`: not present") {
		t.Errorf("the missing rule is named:\n%s", out)
	}
	if strings.Contains(out, "README") {
		t.Errorf("a non-rule file is not mentioned:\n%s", out)
	}
}

func TestGatesNoChangedRulesPasses(t *testing.T) {
	list := filepath.Join(t.TempDir(), "changed")
	if err := os.WriteFile(list, []byte("rules/README.md\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := gates(t, "--changed", list)
	if code != exitOK || !strings.Contains(out, "No rule files changed.") {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestGatesUsageErrors(t *testing.T) {
	list := filepath.Join(t.TempDir(), "changed")
	if err := os.WriteFile(list, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{},
		{"--changed", list, "../../rules/proc_dump.yml"},
		{"--changed", filepath.Join(t.TempDir(), "missing")},
		{"--corpus", "testdata/missing", "../../rules/proc_dump.yml"},
		{"--samples", "0", "../../rules/proc_dump.yml"},
	} {
		code, _, stderr := gates(t, args...)
		if code != exitUsage || stderr == "" {
			t.Errorf("%v: code %d, stderr %q", args, code, stderr)
		}
	}
}

func TestReportEscapesPipesAndStaysUnderTheCommentLimit(t *testing.T) {
	var rules []ruleGates
	for i := 0; i < 400; i++ {
		rg := ruleGates{Path: "rules/a|b.yml"}
		rg.Gates[gParse] = gateResult{Status: gateFail, Note: "does not load", Detail: []string{strings.Repeat("x", 300)}}
		for g := gFixtures; g < numGates; g++ {
			rg.Gates[g] = gateResult{Status: gateSkip}
		}
		rules = append(rules, rg)
	}
	var b strings.Builder
	if err := renderReport(&b, reportHeader{TaxonomyV: "t"}, rules, nil, maxComment); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if len(out) > maxComment {
		t.Fatalf("report is %d bytes, cap %d", len(out), maxComment)
	}
	if !strings.Contains(out, "| `rules/a\\|b.yml` |") {
		t.Errorf("a pipe in a cell must be escaped")
	}
	if !strings.Contains(out, "Details were cut") {
		t.Errorf("a cut report says so")
	}
}

// A large PR has more table rows than one comment holds. The comment keeps
// the failures and warnings, says how many rules it left out, and stays
// under the cap; the unbounded report keeps every row and every detail.
func TestReportWithManyRulesBoundsTheCommentAndNotTheFullReport(t *testing.T) {
	var rules []ruleGates
	for i := 0; i < 3000; i++ {
		rg := ruleGates{Path: fmt.Sprintf("rules/some/fairly/long/directory/name/rule_%04d.yml", i)}
		for g := gParse; g < numGates; g++ {
			rg.Gates[g] = gateResult{Status: gatePass, Note: "fine"}
		}
		switch i {
		case 2500:
			rg.Gates[gFixtures] = gateResult{Status: gateFail, Note: "fixtures disagree", Detail: []string{"case x: want match"}}
		case 2900:
			rg.Gates[gPrefilter] = gateResult{Status: gateWarn, Note: "in Always", Help: "add a literal"}
		}
		rules = append(rules, rg)
	}
	missing := []string{"rules/gone.yml"}

	var full strings.Builder
	if err := renderReport(&full, reportHeader{TaxonomyV: "t"}, rules, missing, 0); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(full.String(), "\n| `rules/"); n != len(rules) {
		t.Fatalf("full report has %d rows, want %d", n, len(rules))
	}
	if !strings.Contains(full.String(), "case x: want match") || strings.Contains(full.String(), "not listed") {
		t.Fatalf("the full report must keep details and cut nothing")
	}

	var comment strings.Builder
	if err := renderReport(&comment, reportHeader{TaxonomyV: "t"}, rules, missing, maxComment); err != nil {
		t.Fatal(err)
	}
	out := comment.String()
	if len(out) > maxComment {
		t.Fatalf("comment is %d bytes, cap %d", len(out), maxComment)
	}
	for _, want := range []string{"rule_2500.yml", "rule_2900.yml", "rules/gone.yml", "3000 rules checked: 1 failed, 1 with warnings"} {
		if !strings.Contains(out, want) {
			t.Errorf("comment lacks %q", want)
		}
	}
	listed := strings.Count(out, "\n| `rules/")
	if listed >= len(rules) || listed < 2 {
		t.Fatalf("comment lists %d rows", listed)
	}
	if want := fmt.Sprintf("%d of %d rules are not listed", len(rules)-listed, len(rules)); !strings.Contains(out, want) {
		t.Errorf("comment lacks %q", want)
	}
	if !strings.HasPrefix(out, reportMarker) {
		t.Errorf("comment lost its marker")
	}
}

// --comment writes the bounded report to a file and stdout keeps the full
// one, so the job summary and the PR comment can come from one run.
func TestGatesCommentFlagWritesASecondReport(t *testing.T) {
	p := copyRule(t, "noisy", "")
	comment := filepath.Join(t.TempDir(), "comment.md")
	code, out, stderr := gates(t, "--comment", comment, p)
	if code != exitOK {
		t.Fatalf("code %d\n%s%s", code, out, stderr)
	}
	b, err := os.ReadFile(comment)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != out {
		t.Fatalf("a small report is the same in both places:\nstdout:\n%s\ncomment:\n%s", out, b)
	}
}

func TestFenceOutgrowsBackticksInContent(t *testing.T) {
	if f := fence([]string{"plain"}); f != "```" {
		t.Errorf("fence %q", f)
	}
	if f := fence([]string{"has ```` four"}); f != "`````" {
		t.Errorf("fence %q", f)
	}
}
