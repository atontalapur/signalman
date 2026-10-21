package sigma

import (
	"errors"
	"os"
	"path/filepath"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/ast"
)

func TestLoadRuleBindsFieldsAndCondition(t *testing.T) {
	tax := loadTax(t)
	r, lerr := LoadRule("testdata/rules/proc_dump.yml", tax)
	if lerr != nil {
		t.Fatalf("load: %v", lerr)
	}
	if r.ID != "1f1a1f1a-0001-4000-8000-000000000001" {
		t.Fatalf("id = %q", r.ID)
	}
	if r.Level != "high" || r.Status != "test" {
		t.Fatalf("level = %q status = %q", r.Level, r.Status)
	}

	matching := &event.Event{Fields: map[string]event.Value{
		"channel":     event.String("Microsoft-Windows-Sysmon/Operational"),
		"event_id":    event.Int(1),
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"CommandLine": event.String(`rundll32.exe comsvcs.dll, MiniDump 624 C:\t.dmp full`),
		"ParentImage": event.String(`C:\Windows\explorer.exe`),
	}}
	if !r.LogSource.Matches(matching) {
		t.Fatal("logsource should match")
	}
	if !ast.Eval(r.Cond, matching) {
		t.Fatal("rule should match the comsvcs minidump event")
	}

	filtered := &event.Event{Fields: map[string]event.Value{
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"CommandLine": event.String(`rundll32.exe comsvcs.dll, MiniDump 624 C:\t.dmp full`),
		"ParentImage": event.String(`C:\Program Files\veeam.exe`),
	}}
	if ast.Eval(r.Cond, filtered) {
		t.Fatal("the veeam filter should suppress the match")
	}
}

func TestLoadRuleReportsTheFieldsItReads(t *testing.T) {
	tax := loadTax(t)
	r, lerr := LoadRule("testdata/rules/proc_dump.yml", tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	want := []string{"CommandLine", "Image", "ParentImage"}
	if len(r.Fields) != len(want) {
		t.Fatalf("fields = %v, want %v", r.Fields, want)
	}
	for i := range want {
		if r.Fields[i] != want[i] {
			t.Fatalf("fields = %v, want %v (sorted)", r.Fields, want)
		}
	}
}

func TestLoadRuleRenamesFieldsThroughTheTaxonomy(t *testing.T) {
	// The security entry maps Image to NewProcessName, so the loaded rule
	// must read the event's field, not the rule's abstract name.
	tax := loadTax(t)
	r, lerr := LoadRule("testdata/rules/list_condition.yml", tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(r.Fields) != 1 || r.Fields[0] != "NewProcessName" {
		t.Fatalf("fields = %v, want [NewProcessName]", r.Fields)
	}
	ev := &event.Event{Fields: map[string]event.Value{
		"NewProcessName": event.String(`C:\Windows\System32\certutil.exe`),
	}}
	if !ast.Eval(r.Cond, ev) {
		t.Fatal("the renamed field must be the one the condition reads")
	}
	if ast.Eval(r.Cond, &event.Event{Fields: map[string]event.Value{
		"Image": event.String(`C:\Windows\System32\certutil.exe`),
	}}) {
		t.Fatal("the rule must not still read the unmapped name")
	}
}

func TestLoadRuleAcceptsAListCondition(t *testing.T) {
	tax := loadTax(t)
	r, lerr := LoadRule("testdata/rules/list_condition.yml", tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	// A list of conditions is an OR, so either selection alone matches.
	for _, image := range []string{`c:\certutil.exe`, `c:\bitsadmin.exe`} {
		ev := &event.Event{Fields: map[string]event.Value{"NewProcessName": event.String(image)}}
		if !ast.Eval(r.Cond, ev) {
			t.Fatalf("%s should match one arm of the list condition", image)
		}
	}
	if ast.Eval(r.Cond, &event.Event{Fields: map[string]event.Value{
		"NewProcessName": event.String(`c:\cmd.exe`),
	}}) {
		t.Fatal("an unrelated image must not match either arm")
	}
}

func TestLoadRuleRejectsAggregationLoudly(t *testing.T) {
	tax := loadTax(t)
	_, lerr := LoadRule("testdata/rules/aggregated.yml", tax)
	if lerr == nil {
		t.Fatal("an aggregation rule must fail to load")
	}
	if lerr.Code != "aggregation" {
		t.Fatalf("code = %q want aggregation", lerr.Code)
	}
	if !strings.Contains(lerr.Reason, "aggregation is not supported") {
		t.Fatalf("reason = %q", lerr.Reason)
	}
	if lerr.RuleID == "" || lerr.Line == 0 {
		t.Fatalf("an aggregation error must carry the rule id and the condition line: %+v", lerr)
	}
	if lerr.Line != 10 {
		t.Fatalf("line = %d, want the condition line 10", lerr.Line)
	}
}

func TestLoadRuleRejectsUnmappedLogsource(t *testing.T) {
	tax := loadTax(t)
	_, lerr := LoadRule("testdata/rules/unmapped.yml", tax)
	if lerr == nil || lerr.Code != "no-taxonomy" {
		t.Fatalf("expected a no-taxonomy failure, got %+v", lerr)
	}
	if !strings.Contains(lerr.Reason, "macos") {
		t.Fatalf("the reason must name the logsource it could not resolve: %q", lerr.Reason)
	}
}

func TestLoadRuleErrorCodes(t *testing.T) {
	tax := loadTax(t)
	cases := map[string]string{
		"no_id.yml":               "missing-id",
		"malformed.yml":           "yaml",
		"no_condition.yml":        "condition",
		"bad_modifier.yml":        "modifier",
		"undefined_selection.yml": "condition",
		"bad_uuid.yml":            "invalid-id",
		"no_level.yml":            "level",
		"bad_level.yml":           "level",
	}
	for file, code := range cases {
		_, lerr := LoadRule(filepath.Join("testdata/rules_bad", file), tax)
		if lerr == nil {
			t.Errorf("%s: expected a rejection", file)
			continue
		}
		if lerr.Code != code {
			t.Errorf("%s: code = %q want %q (reason %q)", file, lerr.Code, code, lerr.Reason)
		}
		if lerr.Path == "" {
			t.Errorf("%s: rejection carries no path", file)
		}
	}
}

// The alerts table stores rule_id as a UUID and severity as an enum of the
// five Sigma levels. A rule outside either loads, matches, and then produces
// an alert no insert can hold, so the loader refuses it instead.
func TestLoadRuleRequiresCanonicalUUIDAndKnownLevel(t *testing.T) {
	tax := loadTax(t)
	const rest = "logsource:\n  product: windows\n  category: process_creation\n" +
		"detection:\n  selection:\n    Image: x\n  condition: selection\n"
	ok := "1f1a1f1a-000e-4000-8000-00000000000e"
	cases := []struct {
		id, level, code string
	}{
		{ok, "informational", ""},
		{ok, "low", ""},
		{ok, "medium", ""},
		{ok, "high", ""},
		{ok, "critical", ""},
		{strings.ToUpper(ok), "high", ""},
		{"{" + ok + "}", "high", CodeInvalidID},
		{"urn:uuid:" + ok, "high", CodeInvalidID},
		{strings.ReplaceAll(ok, "-", ""), "high", CodeInvalidID},
		{ok[:35] + "g", "high", CodeInvalidID},
		{"proc_dump", "high", CodeInvalidID},
		{ok, "", CodeLevel},
		{ok, "High", CodeLevel},
		{ok, "severe", CodeLevel},
	}
	for _, c := range cases {
		src := "title: t\nid: '" + c.id + "'\n"
		if c.level != "" {
			src += "level: " + c.level + "\n"
		}
		_, lerr := LoadRuleBytes("r.yml", []byte(src+rest), tax)
		got := ""
		if lerr != nil {
			got = lerr.Code
		}
		if got != c.code {
			t.Errorf("id %q level %q: code %q, want %q (%v)", c.id, c.level, got, c.code, lerr)
		}
		if lerr != nil && lerr.RuleID != c.id {
			t.Errorf("id %q: rejection names rule %q", c.id, lerr.RuleID)
		}
	}
}

// An aggregation is reported as one even on a rule that also lacks a
// level, so the corpus acceptance report keeps measuring the engine.
func TestLoadRuleReportsAggregationBeforeLevel(t *testing.T) {
	tax := loadTax(t)
	src := "title: t\nid: 1f1a1f1a-000f-4000-8000-00000000000f\n" +
		"logsource:\n  product: windows\n  category: process_creation\n" +
		"detection:\n  selection:\n    EventID: 1\n  condition: selection | count() > 5\n"
	_, lerr := LoadRuleBytes("r.yml", []byte(src), tax)
	if lerr == nil || lerr.Code != CodeAggregation {
		t.Fatalf("got %v, want an aggregation rejection", lerr)
	}
}

func TestLoadErrorMessageCarriesEveryField(t *testing.T) {
	e := &LoadError{Path: "rules/x.yml", RuleID: "abc", Code: "aggregation", Reason: "nope", Line: 12}
	msg := e.Error()
	for _, want := range []string{"rules/x.yml", "12", "aggregation", "abc", "nope"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q omits %q", msg, want)
		}
	}
}

func TestLoadRuleMissingFileIsAnError(t *testing.T) {
	tax := loadTax(t)
	if _, lerr := LoadRule("testdata/rules/does_not_exist.yml", tax); lerr == nil {
		t.Fatal("a missing file must be a rejection, not a nil rule with no error")
	}
}

func TestLoadRuleBytesTakesSourceDirectly(t *testing.T) {
	tax := loadTax(t)
	src, err := os.ReadFile("testdata/rules/proc_dump.yml")
	if err != nil {
		t.Fatal(err)
	}
	r, lerr := LoadRuleBytes("in-memory.yml", src, tax)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if r.Path != "in-memory.yml" {
		t.Fatalf("path = %q", r.Path)
	}
}

func TestLoadRuleSetIsDeterministic(t *testing.T) {
	tax := loadTax(t)
	a, aerrs, err := LoadRuleSet("testdata/rules", tax)
	if err != nil {
		t.Fatal(err)
	}
	b, berrs, err := LoadRuleSet("testdata/rules", tax)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != b.Version {
		t.Fatal("RuleSetV must be stable across loads")
	}
	if a.TaxonomyV != tax.Version {
		t.Fatal("the rule set must carry the taxonomy version")
	}
	if len(a.Rules) != 2 {
		t.Fatalf("expected 2 loadable rules, got %d", len(a.Rules))
	}
	if len(aerrs) != 2 || len(berrs) != 2 {
		t.Fatalf("expected 2 rejections, got %d and %d", len(aerrs), len(berrs))
	}
	if a.Rules[0].ID > a.Rules[1].ID {
		t.Fatal("rules must be sorted by id")
	}
}

func TestLoadRuleSetRejectsADuplicateID(t *testing.T) {
	tax := loadTax(t)
	rs, errs, err := LoadRuleSet("testdata/rules_dup", tax)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("the first claim on an id loads, the second does not: got %d rules", len(rs.Rules))
	}
	if len(errs) != 1 || errs[0].Code != "duplicate-id" {
		t.Fatalf("expected one duplicate-id rejection, got %+v", errs)
	}
	for _, want := range []string{"first.yml", "second.yml"} {
		if !strings.Contains(errs[0].Reason, want) {
			t.Errorf("reason %q does not name %q", errs[0].Reason, want)
		}
	}
}

// A UUID is one value whatever the case of its hex. The loader lowers the
// id before anything compares or stores it, so two spellings of one id are
// a duplicate and not two rules writing the same alerts row.
func TestLoadRuleSetRejectsADuplicateIDInAnotherCase(t *testing.T) {
	tax := loadTax(t)
	rs, errs, err := LoadRuleSet("testdata/rules_dup_case", tax)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("one id in two cases loads once: got %d rules", len(rs.Rules))
	}
	if len(errs) != 1 || errs[0].Code != CodeDuplicateID {
		t.Fatalf("expected one duplicate-id rejection, got %+v", errs)
	}
	if want := "1f1a1f1a-000a-4000-8000-00000000000a"; errs[0].RuleID != want {
		t.Errorf("rejection names %q, want %q", errs[0].RuleID, want)
	}
}

func TestLoadRuleLowersTheID(t *testing.T) {
	src := "title: t\nid: 1F1A1F1A-000B-4000-8000-00000000000B\nlevel: low\n" +
		"logsource:\n  product: windows\n  category: process_creation\n" +
		"detection:\n  selection:\n    Image: x\n  condition: selection\n"
	r, lerr := LoadRuleBytes("r.yml", []byte(src), loadTax(t))
	if lerr != nil {
		t.Fatal(lerr)
	}
	if want := "1f1a1f1a-000b-4000-8000-00000000000b"; r.ID != want {
		t.Errorf("ID %q, want %q", r.ID, want)
	}
}

func TestRuleSetVersionTracksRuleContent(t *testing.T) {
	tax := loadTax(t)
	base, _, err := LoadRuleSet("testdata/rules", tax)
	if err != nil {
		t.Fatal(err)
	}

	// One changed detection value has to move RuleSetV, or a rule edit
	// could ship without the verdict stream admitting that anything changed.
	dir := t.TempDir()
	for _, name := range []string{"proc_dump.yml", "list_condition.yml"} {
		src, err := os.ReadFile(filepath.Join("testdata/rules", name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "proc_dump.yml" {
			src = []byte(strings.Replace(string(src), "comsvcs.dll", "comsvcs2.dll", 1))
		}
		if err := os.WriteFile(filepath.Join(dir, name), src, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	edited, _, err := LoadRuleSet(dir, tax)
	if err != nil {
		t.Fatal(err)
	}
	if edited.Version == base.Version {
		t.Fatal("RuleSetV must change when a detection value changes")
	}
}

func TestRuleSetVersionTracksTheTaxonomy(t *testing.T) {
	tax := loadTax(t)
	base, _, err := LoadRuleSet("testdata/rules", tax)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	src, err := os.ReadFile("testdata/taxonomy/sysmon.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sysmon.yml"),
		[]byte(strings.Replace(string(src), "event_id: 1", "event_id: 2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	other, err := LoadTaxonomy(dir)
	if err != nil {
		t.Fatal(err)
	}
	moved, _, err := LoadRuleSet("testdata/rules", other)
	if err != nil {
		t.Fatal(err)
	}
	if moved.Version == base.Version {
		t.Fatal("RuleSetV must change when the taxonomy it was bound against changes")
	}
}

func TestLoadRuleSetMissingDirIsAnError(t *testing.T) {
	tax := loadTax(t)
	if _, _, err := LoadRuleSet("testdata/does_not_exist", tax); err == nil {
		t.Fatal("a missing rule directory is an operator error, not an empty rule set")
	}
}

func TestLoadRuleReportsExpressibilityBeforeTaxonomy(t *testing.T) {
	// A rule this engine cannot express must say so even when its logsource
	// is unmapped, so the corpus acceptance report counts engine gaps
	// separately from sources this deployment does not ingest.
	tax := loadTax(t)
	src := []byte(`
title: Aggregated on a source nobody mapped
id: 1f1a1f1a-000a-4000-8000-00000000000a
level: low
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith: '/curl'
  condition: selection | count() > 5
`)
	_, lerr := LoadRuleBytes("synthetic.yml", src, tax)
	if lerr == nil {
		t.Fatal("expected a rejection")
	}
	if lerr.Code != CodeAggregation {
		t.Fatalf("code = %q, want %q", lerr.Code, CodeAggregation)
	}
}

func TestLoadRuleReportsModifierGapsBeforeTaxonomy(t *testing.T) {
	tax := loadTax(t)
	src := []byte(`
title: Unsupported modifier on an unmapped source
id: 1f1a1f1a-000b-4000-8000-00000000000b
level: low
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    CommandLine|expandvar: x
  condition: selection
`)
	_, lerr := LoadRuleBytes("synthetic.yml", src, tax)
	if lerr == nil || lerr.Code != CodeModifier {
		t.Fatalf("want a modifier rejection, got %+v", lerr)
	}
}

// A detection error keeps its cause, so a caller can tell an RE2 syntax
// rejection from other detection errors by type rather than by message.
// The message quotes the rule's value, so text matching can be forged by
// the value.
func TestLoadErrorUnwrapsDetectionCause(t *testing.T) {
	src := []byte(`title: t
id: 00000000-0000-4000-8000-000000000000
level: low
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|re: '(?<!a)b'
  condition: selection
`)
	_, lerr := LoadRuleBytes("re.yml", src, loadTax(t))
	if lerr == nil {
		t.Fatal("expected RE2 to reject a lookbehind")
	}
	if lerr.Code != CodeDetection {
		t.Fatalf("code = %q, want %q", lerr.Code, CodeDetection)
	}
	var synErr *syntax.Error
	if !errors.As(lerr, &synErr) {
		t.Fatalf("LoadError does not unwrap to *syntax.Error: %v", lerr)
	}
}
