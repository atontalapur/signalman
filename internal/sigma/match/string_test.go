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
	if hit(t, Any(ms), event.String("xxc")) {
		t.Fatal("any fails when no value matches")
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
		if got := padTrailingBackslash(c.in); got != c.want {
			t.Errorf("padTrailingBackslash(%q) = %q want %q", c.in, got, c.want)
		}
	}
	if !hit(t, EndsWith(`\`), event.String(`C:\Temp\`)) {
		t.Fatal("endswith a lone backslash must match a trailing backslash")
	}
	if !hit(t, Contains(`\Temp\`), event.String(`C:\Temp\x.exe`)) {
		t.Fatal("contains with a trailing backslash must not swallow the star")
	}
}

// A single value is returned as is, with no wrapper. The result must still
// behave like the wrapped matcher.
func TestAnyAllSingleElementShortcut(t *testing.T) {
	one := []Matcher{Contains("a")}
	if !hit(t, Any(one), event.String("xa")) || hit(t, Any(one), event.String("xb")) {
		t.Fatal("any over one value is that value")
	}
	if !hit(t, All(one), event.String("xa")) || hit(t, All(one), event.String("xb")) {
		t.Fatal("all over one value is that value")
	}
}

// Sigma allows wildcards inside contains, startswith, and endswith values.
// The modifier appends its own stars but leaves the author's alone.
func TestModifiersKeepAuthorWildcards(t *testing.T) {
	cases := []struct {
		name string
		m    Matcher
		in   string
		want bool
	}{
		{"contains star", Contains("a*b"), "xxaYYbxx", true},
		{"contains star no b", Contains("a*b"), "xxaYYxx", false},
		{"contains escaped star", Contains(`a\*b`), "xxa*bxx", true},
		{"contains escaped star not wildcard", Contains(`a\*b`), "xxaYYbxx", false},
		{"contains question", Contains("a?b"), "xxaXbxx", true},
		{"startswith star", StartsWith("a*b"), "aYYbzz", true},
		{"startswith star wrong prefix", StartsWith("a*b"), "zaYYb", false},
		{"endswith star", EndsWith("a*b"), "zzaYYb", true},
		{"endswith star wrong suffix", EndsWith("a*b"), "aYYbz", false},
		{"contains empty", Contains(""), "anything", true},
		{"startswith empty", StartsWith(""), "", true},
	}
	for _, c := range cases {
		if got := hit(t, c.m, event.String(c.in)); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// A list may hold nulls. They have no text and are skipped, not matched.
func TestListWithNullElement(t *testing.T) {
	v := event.List(event.Null(), event.String("needle"))
	if !hit(t, Equals("needle"), v) {
		t.Fatal("a null element does not stop the scan")
	}
	if hit(t, Equals(""), event.List(event.Null())) {
		t.Fatal("a list of only nulls has no text to match")
	}
	if hit(t, Null(), event.List(event.Null())) {
		t.Fatal("null matches only a null value, not a list containing one")
	}
}

// Callers must pass a non-empty slice; Build guarantees it. These pin the
// vacuous results so a future caller cannot be surprised by them.
func TestAnyAllEmpty(t *testing.T) {
	if hit(t, Any(nil), event.String("x")) {
		t.Fatal("Any of nothing is false")
	}
	if !hit(t, All(nil), event.String("x")) {
		t.Fatal("All of nothing is true")
	}
}
