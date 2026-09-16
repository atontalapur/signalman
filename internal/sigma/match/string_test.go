package match

import (
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func hit(t *testing.T, m Matcher, v event.Value) bool {
	t.Helper()
	return m.Match(v, &event.Event{Fields: map[string]event.Value{}})
}

func TestStringMatchersAreCaseInsensitive(t *testing.T) {
	if !hit(t, Equals("PowerShell.exe"), event.String("powershell.EXE")) {
		t.Fatal("equals must fold case")
	}
	if !hit(t, Contains("comsvcs"), event.String("rundll32 COMSVCS.dll,MiniDump")) {
		t.Fatal("contains must fold case")
	}
	if !hit(t, StartsWith(`C:\Win`), event.String(`c:\windows\system32`)) {
		t.Fatal("startswith must fold case")
	}
	if !hit(t, EndsWith(`\rundll32.exe`), event.String(`C:\Windows\System32\RUNDLL32.EXE`)) {
		t.Fatal("endswith must fold case")
	}
}

func TestEqualsHonorsWildcards(t *testing.T) {
	if !hit(t, Equals(`*\rundll32.exe`), event.String(`C:\Windows\rundll32.exe`)) {
		t.Fatal("equals with a star behaves as a wildcard match")
	}
}

func TestNumbersAndBoolsCompareAsText(t *testing.T) {
	if !hit(t, Equals("4688"), event.Int(4688)) {
		t.Fatal("int should compare against its decimal text")
	}
	if !hit(t, Equals("true"), event.Bool(true)) {
		t.Fatal("bool should compare against its text")
	}
}

func TestListValueMatchesAnyElement(t *testing.T) {
	v := event.List(event.String("a"), event.String("needle"))
	if !hit(t, Equals("needle"), v) {
		t.Fatal("a list value matches when any element matches")
	}
	if hit(t, Equals("missing"), v) {
		t.Fatal("a list value does not match when no element matches")
	}
}

func TestRegexCaseSensitivityDefault(t *testing.T) {
	m, err := Regex(`^powershell`, false)
	if err != nil {
		t.Fatal(err)
	}
	if hit(t, m, event.String("PowerShell")) {
		t.Fatal("re is case sensitive by default, unlike every other string modifier")
	}
	mi, err := Regex(`^powershell`, true)
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, mi, event.String("PowerShell")) {
		t.Fatal("re|i must fold case")
	}
	if _, err := Regex(`(`, false); err == nil {
		t.Fatal("an invalid regex must be an error")
	}
}

func TestNullMatchesAbsentAndExplicitNull(t *testing.T) {
	if !hit(t, Null(), event.Null()) {
		t.Fatal("null matcher must match a null value")
	}
	if hit(t, Null(), event.String("")) {
		t.Fatal("null must not match an empty string")
	}
	if hit(t, Equals(""), event.Null()) {
		t.Fatal("empty string must not match null")
	}
	if !hit(t, Equals(""), event.String("")) {
		t.Fatal("empty string matches a present empty string")
	}
}

func TestAnyAll(t *testing.T) {
	ms := []Matcher{Contains("a"), Contains("b")}
	if !hit(t, Any(ms), event.String("xxa")) {
		t.Fatal("any is an OR over values")
	}
	if hit(t, All(ms), event.String("xxa")) {
		t.Fatal("all is an AND over values")
	}
	if !hit(t, All(ms), event.String("xxab")) {
		t.Fatal("all matches when every value is present")
	}
}

// A value ending in an odd run of backslashes would otherwise escape the
// star the modifier appends. Rows follow the Sigma escape table.
func TestEscapeWildcardsTrailingBackslashes(t *testing.T) {
	cases := []struct{ in, want string }{
		{`a`, `a`},
		{`a\`, `a\\`},
		{`a\\`, `a\\`},
		{`a\\\`, `a\\\\`},
		{`a\\\\`, `a\\\\`},
	}
	for _, c := range cases {
		if got := escapeWildcards(c.in); got != c.want {
			t.Errorf("escapeWildcards(%q) = %q want %q", c.in, got, c.want)
		}
	}
	if !hit(t, EndsWith(`\`), event.String(`C:\Temp\`)) {
		t.Fatal("endswith a lone backslash must match a trailing backslash")
	}
	if !hit(t, Contains(`\Temp\`), event.String(`C:\Temp\x.exe`)) {
		t.Fatal("contains with a trailing backslash must not swallow the star")
	}
}
