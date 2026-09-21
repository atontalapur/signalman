package sigma

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma/ast"
	"gopkg.in/yaml.v3"
)

func compileYAML(t *testing.T, src string) (map[string]ast.Node, []string) {
	t.Helper()
	raw := decodeDetection(t, src)
	sels, names, err := CompileDetection(raw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return sels, names
}

func decodeDetection(t *testing.T, src string) map[string]any {
	t.Helper()
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(src), &raw); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	return raw
}

func evalSel(t *testing.T, n ast.Node, fields map[string]event.Value) bool {
	t.Helper()
	return ast.Eval(n, &event.Event{Fields: fields})
}

func TestDetectionMapIsAndAcrossFields(t *testing.T) {
	sels, names := compileYAML(t, `
selection:
  Image|endswith: '\rundll32.exe'
  CommandLine|contains: comsvcs
condition: selection
`)
	if len(names) != 1 || names[0] != "selection" {
		t.Fatalf("names = %v", names)
	}
	both := map[string]event.Value{
		"Image":       event.String(`C:\Windows\System32\rundll32.exe`),
		"CommandLine": event.String("rundll32 comsvcs.dll,MiniDump"),
	}
	one := map[string]event.Value{
		"Image": event.String(`C:\Windows\System32\rundll32.exe`),
	}
	if !evalSel(t, sels["selection"], both) {
		t.Fatal("both fields present should match")
	}
	if evalSel(t, sels["selection"], one) {
		t.Fatal("fields combine with AND")
	}
}

func TestDetectionValueListIsOr(t *testing.T) {
	sels, _ := compileYAML(t, `
selection:
  EventID:
    - 1
    - 4688
condition: selection
`)
	if !evalSel(t, sels["selection"], map[string]event.Value{"EventID": event.Int(4688)}) {
		t.Fatal("a value list is an OR")
	}
	if evalSel(t, sels["selection"], map[string]event.Value{"EventID": event.Int(9)}) {
		t.Fatal("a value not in the list should not match")
	}
}

func TestDetectionListOfMapsIsOrOfAnds(t *testing.T) {
	sels, _ := compileYAML(t, `
selection:
  - Image|endswith: '\a.exe'
    User: SYSTEM
  - Image|endswith: '\b.exe'
condition: selection
`)
	if !evalSel(t, sels["selection"], map[string]event.Value{
		"Image": event.String(`c:\b.exe`),
	}) {
		t.Fatal("the second map alone should match")
	}
	if evalSel(t, sels["selection"], map[string]event.Value{
		"Image": event.String(`c:\a.exe`),
	}) {
		t.Fatal("the first map needs both of its fields")
	}
}

func TestDetectionNullVersusEmptyString(t *testing.T) {
	sels, _ := compileYAML(t, `
missing:
  ParentImage: null
empty:
  ParentImage: ''
condition: missing
`)
	absent := map[string]event.Value{}
	explicitNull := map[string]event.Value{"ParentImage": event.Null()}
	emptyStr := map[string]event.Value{"ParentImage": event.String("")}

	if !evalSel(t, sels["missing"], absent) {
		t.Fatal("null matches an absent field")
	}
	if !evalSel(t, sels["missing"], explicitNull) {
		t.Fatal("null matches an explicit null")
	}
	if evalSel(t, sels["missing"], emptyStr) {
		t.Fatal("null must not match an empty string")
	}
	if evalSel(t, sels["empty"], absent) {
		t.Fatal("empty string must not match an absent field")
	}
	if !evalSel(t, sels["empty"], emptyStr) {
		t.Fatal("empty string matches a present empty string")
	}
}

func TestDetectionKeywordsListIsOrOverAllFields(t *testing.T) {
	sels, _ := compileYAML(t, `
keywords:
  - MiniDump
  - lsass
condition: keywords
`)
	if !evalSel(t, sels["keywords"], map[string]event.Value{
		"CommandLine": event.String("procdump -ma lsass.exe out.dmp"),
	}) {
		t.Fatal("a bare keyword list searches every field value")
	}
	if evalSel(t, sels["keywords"], map[string]event.Value{
		"CommandLine": event.String("whoami"),
	}) {
		t.Fatal("no field carries either keyword")
	}
}

func TestDetectionKeywordSearchesListFieldValues(t *testing.T) {
	sels, _ := compileYAML(t, `
keywords:
  - lsass
condition: keywords
`)
	if !evalSel(t, sels["keywords"], map[string]event.Value{
		"Args": event.List(event.String("-ma"), event.String("lsass.exe")),
	}) {
		t.Fatal("a keyword must reach inside a list-valued field")
	}
}

func TestDetectionScalarSelectionIsAKeyword(t *testing.T) {
	sels, _ := compileYAML(t, `
keywords: lsass
condition: keywords
`)
	if !evalSel(t, sels["keywords"], map[string]event.Value{
		"CommandLine": event.String("dump lsass"),
	}) {
		t.Fatal("a bare scalar selection is a single keyword")
	}
}

func TestDetectionNamesAreSortedAndExcludeCondition(t *testing.T) {
	_, names := compileYAML(t, `
selection_b:
  A: 1
filter_a:
  B: 2
selection_a:
  C: 3
condition: selection_* and not filter_a
`)
	want := []string{"filter_a", "selection_a", "selection_b"}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names = %v, want %v", names, want)
		}
	}
}

func TestDetectionIsDeterministic(t *testing.T) {
	src := `
selection:
  A: 1
  B: 2
  C: 3
condition: selection
`
	first, _ := compileYAML(t, src)
	want := ast.String(first["selection"])
	for i := 0; i < 20; i++ {
		got, _ := compileYAML(t, src)
		if ast.String(got["selection"]) != want {
			t.Fatalf("tree shape varies across runs: %s vs %s", ast.String(got["selection"]), want)
		}
	}
}

func TestDetectionRejectsEmptyAndBadShapes(t *testing.T) {
	cases := map[string]string{
		"empty list":      "selection: []\ncondition: selection\n",
		"empty map":       "selection: {}\ncondition: selection\n",
		"nested map":      "selection:\n  Outer:\n    Inner: 1\ncondition: selection\n",
		"bad modifier":    "selection:\n  A|expandvar: 1\ncondition: selection\n",
		"bad chain":       "selection:\n  A|re|contains: 1\ncondition: selection\n",
		"list in a value": "selection:\n  A:\n    - - 1\ncondition: selection\n",
	}
	for name, src := range cases {
		_, _, err := CompileDetection(decodeDetection(t, src))
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestDetectionErrorNamesTheSelectionAndField(t *testing.T) {
	_, _, err := CompileDetection(decodeDetection(t,
		"selection_susp:\n  CommandLine|expandvar: x\ncondition: selection_susp\n"))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"selection_susp", "CommandLine|expandvar", "expandvar"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

func TestToValueKinds(t *testing.T) {
	cases := []struct {
		in   any
		want event.Value
	}{
		{nil, event.Null()},
		{"x", event.String("x")},
		{4688, event.Int(4688)},
		{int64(4688), event.Int(4688)},
		{float64(4688), event.Int(4688)},
		{true, event.Bool(true)},
	}
	for _, c := range cases {
		got, err := toValue(c.in)
		if err != nil {
			t.Fatalf("toValue(%v): %v", c.in, err)
		}
		if got.Kind != c.want.Kind {
			t.Errorf("toValue(%v) kind = %s, want %s", c.in, got.Kind, c.want.Kind)
		}
	}
}

func TestToValueRejectsUnsupportedTypeNamingIt(t *testing.T) {
	_, err := toValue(map[string]any{"a": 1})
	if err == nil || !strings.Contains(err.Error(), "map[string]interface {}") {
		t.Fatalf("want an error naming the type, got %v", err)
	}
}

func TestToValueFractionalFloatKeepsItsText(t *testing.T) {
	v, err := toValue(1.5)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := v.Text()
	if !ok || s != "1.5" {
		t.Fatalf("toValue(1.5) = %q, %v", s, ok)
	}
}
