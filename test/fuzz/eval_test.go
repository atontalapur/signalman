package fuzz

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

func TestBridgeable(t *testing.T) {
	valid := Fields{"Image": `C:\Windows\rundll32.exe`}
	if !bridgeable(seedRule, valid) {
		t.Fatal("a valid-UTF8 rule and event must be bridgeable")
	}
	if bridgeable(string([]byte{0xff, 0xfe}), valid) {
		t.Fatal("invalid UTF-8 in the rule YAML must not be bridgeable: JSON cannot carry it losslessly")
	}
	invalidKey := Fields{string([]byte{0xff}): "x"}
	if bridgeable(seedRule, invalidKey) {
		t.Fatal("invalid UTF-8 in an event field name must not be bridgeable")
	}
	invalidValue := Fields{"Image": string([]byte{0xff})}
	if bridgeable(seedRule, invalidValue) {
		t.Fatal("invalid UTF-8 in an event field value must not be bridgeable")
	}
}

func TestMissingField(t *testing.T) {
	ev := Fields{"Image": "a.exe", "User": "alice"}
	if missingField([]string{"Image", "User"}, ev) {
		t.Fatal("missingField must be false when every read field is present")
	}
	if !missingField([]string{"Image", "CommandLine"}, ev) {
		t.Fatal("missingField must be true when a read field is absent from the event")
	}
	if missingField(nil, ev) {
		t.Fatal("a rule that reads no fields cannot have a missing one")
	}
}

func TestEvalOnceRejectsUnresolvableTaxonomyDir(t *testing.T) {
	if _, err := EvalOnce([]byte(seedRule), "does/not/exist", Fields{"Image": "a.exe"}); err == nil {
		t.Fatal("EvalOnce with a taxonomy directory that cannot load must return an error, not a false verdict")
	}
}

func TestEvalOnceRejectsRuleMissingID(t *testing.T) {
	rule := `title: no id
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: x
  condition: selection
`
	_, err := EvalOnce([]byte(rule), taxonomyDir, Fields{"Image": "x"})
	if err == nil {
		t.Fatal("EvalOnce must reject a rule with no id")
	}
	if !strings.Contains(err.Error(), "missing-id") {
		t.Fatalf("EvalOnce error = %v, want it to name missing-id", err)
	}
}

// buildEvent is tested directly against a synthetic taxonomy entry so the
// rename, identity, and match-overwrite branches are pinned without loading
// the real taxonomy files.
func TestBuildEvent(t *testing.T) {
	entry := &sigma.TaxonomyEntry{
		Fields: map[string]string{"Image": "NewProcessName"},
		Match:  map[string]event.Value{"channel": event.String("Microsoft-Windows-Sysmon/Operational")},
	}
	raw := Fields{
		"Image":       `C:\Windows\cmd.exe`,
		"CommandLine": `cmd.exe /c whoami`,
		"channel":     "attacker-controlled-value",
	}

	ev := buildEvent(entry, raw)

	if got, ok := ev.Fields["NewProcessName"]; !ok || got.S != `C:\Windows\cmd.exe` {
		t.Fatalf("Image should have been renamed to NewProcessName, got fields=%+v", ev.Fields)
	}
	if _, ok := ev.Fields["Image"]; ok {
		t.Fatal("the pre-rename field name must not survive alongside the mapped one")
	}
	if got, ok := ev.Fields["CommandLine"]; !ok || got.S != `cmd.exe /c whoami` {
		t.Fatalf("an unmapped field must pass through under its own name, got fields=%+v", ev.Fields)
	}
	if got := ev.Fields["channel"]; got.S != "Microsoft-Windows-Sysmon/Operational" {
		t.Fatalf("the taxonomy's match criteria must win over a raw event field with the same name, got %q", got.S)
	}
}

func TestDeclaredLogSource(t *testing.T) {
	rule := `title: t
logsource:
  product: windows
  service: security
  category: process_creation
detection:
  selection:
    Image: x
  condition: selection
`
	ls, err := declaredLogSource([]byte(rule))
	if err != nil {
		t.Fatalf("declaredLogSource: %v", err)
	}
	want := sigma.LogSource{Product: "windows", Service: "security", Category: "process_creation"}
	if ls != want {
		t.Fatalf("declaredLogSource = %+v, want %+v", ls, want)
	}

	if _, err := declaredLogSource([]byte("not: [valid yaml")); err == nil {
		t.Fatal("declaredLogSource must report an error for YAML it cannot parse")
	}
}

// Without its venv the oracle tests skip, which is right on a laptop and
// wrong in CI: a CI job whose venv step broke would go green having run
// none of them.
func TestMissingOracleIsFatalInCI(t *testing.T) {
	cases := []struct {
		available bool
		ci        string
		want      oracleState
	}{
		{true, "", oracleRun},
		{true, "true", oracleRun},
		{false, "", oracleSkip},
		{false, "false", oracleSkip},
		{false, "true", oracleFatal},
	}
	for _, c := range cases {
		if got := oracleStatus(c.available, c.ci); got != c.want {
			t.Errorf("oracleStatus(%v, %q) = %v, want %v", c.available, c.ci, got, c.want)
		}
	}
}

func TestBuildEventKeepsValueTypes(t *testing.T) {
	entry := &sigma.TaxonomyEntry{Fields: map[string]string{}, Match: map[string]event.Value{}}
	ev := buildEvent(entry, Fields{"s": "x", "i": int64(443), "n": nil})
	if v := ev.Fields["s"]; v.Kind != event.KindString || v.S != "x" {
		t.Fatalf("string field = %+v", v)
	}
	if v := ev.Fields["i"]; v.Kind != event.KindInt || v.I != 443 {
		t.Fatalf("int field = %+v", v)
	}
	if v, ok := ev.Fields["n"]; !ok || v.Kind != event.KindNull {
		t.Fatalf("null field = %+v, present=%v; want a present null", v, ok)
	}
}

// A null field read under a negation lands in the same SQL three-valued
// logic gap as an absent one, and only then.
func TestNullUnderNegation(t *testing.T) {
	ev := Fields{"Image": nil, "User": "alice"}
	if !nullUnderNegation([]string{"Image"}, ev, "not selection") {
		t.Fatal("a negated rule reading a null field is the documented gap")
	}
	if nullUnderNegation([]string{"Image"}, ev, "selection") {
		t.Fatal("without a negation there is no gap to suppress")
	}
	if nullUnderNegation([]string{"User"}, ev, "not selection") {
		t.Fatal("a rule that reads no null field is not in the gap")
	}
}

// Typed values reach both engines and the two agree on the plain cases.
func TestOracleAgreesOnTypedValues(t *testing.T) {
	requireOracle(t)
	o, err := StartOracle()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	cases := []struct {
		name  string
		key   string
		value string
		image any
		want  bool
	}{
		{"int equals its digits", "Image", `"443"`, int64(443), true},
		{"int differs", "Image", `"443"`, int64(80), false},
		{"int is compared by its digits", "Image", `"0443"`, int64(443), false},
		{"int contains", "Image|contains", `"44"`, int64(443), true},
		{"null never matches", "Image", `"x"`, nil, false},
		{"null never contains", "Image|contains", `"x"`, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule := strings.Replace(seedRule, `Image|endswith: '\rundll32.exe'`, c.key+": "+c.value, 1)
			ev := Fields{"Image": c.image}
			got, err := EvalOnce([]byte(rule), taxonomyDir, ev)
			if err != nil {
				t.Fatal(err)
			}
			want, _, err := o.Eval(rule, ev)
			if err != nil {
				t.Fatalf("oracle: %v", err)
			}
			if got != want || got != c.want {
				t.Fatalf("signalman=%v oracle=%v, want %v", got, want, c.want)
			}
		})
	}
}
