package fuzz

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
	"github.com/atontalapur/signalman/internal/sigma"
)

func TestBridgeable(t *testing.T) {
	valid := map[string]string{"Image": `C:\Windows\rundll32.exe`}
	if !bridgeable(seedRule, valid) {
		t.Fatal("a valid-UTF8 rule and event must be bridgeable")
	}
	if bridgeable(string([]byte{0xff, 0xfe}), valid) {
		t.Fatal("invalid UTF-8 in the rule YAML must not be bridgeable: JSON cannot carry it losslessly")
	}
	invalidKey := map[string]string{string([]byte{0xff}): "x"}
	if bridgeable(seedRule, invalidKey) {
		t.Fatal("invalid UTF-8 in an event field name must not be bridgeable")
	}
	invalidValue := map[string]string{"Image": string([]byte{0xff})}
	if bridgeable(seedRule, invalidValue) {
		t.Fatal("invalid UTF-8 in an event field value must not be bridgeable")
	}
}

func TestMissingField(t *testing.T) {
	ev := map[string]string{"Image": "a.exe", "User": "alice"}
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
	if _, err := EvalOnce([]byte(seedRule), "does/not/exist", map[string]string{"Image": "a.exe"}); err == nil {
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
	_, err := EvalOnce([]byte(rule), taxonomyDir, map[string]string{"Image": "x"})
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
	raw := map[string]string{
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
