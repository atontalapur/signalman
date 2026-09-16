package match

import (
	"errors"
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func build(t *testing.T, mods string, vals ...string) Matcher {
	t.Helper()
	var vs []event.Value
	for _, v := range vals {
		vs = append(vs, event.String(v))
	}
	var ms []string
	if mods != "" {
		ms = strings.Split(mods, "|")
	}
	m, err := Build(ms, vs)
	if err != nil {
		t.Fatalf("Build(%q): %v", mods, err)
	}
	return m
}

func TestBuildPlainIsEquals(t *testing.T) {
	m := build(t, "", "cmd.exe")
	if !hit(t, m, event.String("CMD.EXE")) || hit(t, m, event.String("cmd.exe.bak")) {
		t.Fatal("no modifier is a case-insensitive equals")
	}
}

func TestBuildListIsOr(t *testing.T) {
	m := build(t, "contains", "alpha", "beta")
	if !hit(t, m, event.String("xxbetaxx")) {
		t.Fatal("a value list is an OR")
	}
}

func TestBuildAllIsAnd(t *testing.T) {
	m := build(t, "contains|all", "alpha", "beta")
	if hit(t, m, event.String("xxbetaxx")) {
		t.Fatal("all requires every value")
	}
	if !hit(t, m, event.String("alpha beta")) {
		t.Fatal("all matches when every value is present")
	}
}

func TestBuildStartsEndsWith(t *testing.T) {
	if !hit(t, build(t, "startswith", `C:\Win`), event.String(`c:\windows`)) {
		t.Fatal("startswith")
	}
	if !hit(t, build(t, "endswith", `\cmd.exe`), event.String(`C:\CMD.EXE`)) {
		t.Fatal("endswith")
	}
}

func TestBuildRegexDefaultsCaseSensitive(t *testing.T) {
	m := build(t, "re", "^Power")
	if hit(t, m, event.String("powershell")) {
		t.Fatal("re is case sensitive by default")
	}
	mi := build(t, "re|i", "^Power")
	if !hit(t, mi, event.String("powershell")) {
		t.Fatal("re|i folds case")
	}
}

func TestBuildRejectsUnknownModifier(t *testing.T) {
	_, err := Build([]string{"expandvar"}, []event.Value{event.String("x")})
	if err == nil || !strings.Contains(err.Error(), "expandvar") {
		t.Fatalf("expected an error naming the modifier, got %v", err)
	}
	if !errors.Is(err, ErrUnsupportedModifier) {
		t.Fatalf("error must wrap ErrUnsupportedModifier, got %v", err)
	}
}

func TestBuildRejectsBadChains(t *testing.T) {
	cases := []string{
		"contains|startswith", // two comparisons
		"re|contains",         // two comparisons
		"i",                   // i without re
		"contains|i",          // i without re
		"base64",              // not in this step; still unsupported
	}
	for _, mods := range cases {
		_, err := Build(strings.Split(mods, "|"), []event.Value{event.String("x")})
		if err == nil {
			t.Errorf("Build(%q): expected an error", mods)
			continue
		}
		if !errors.Is(err, ErrUnsupportedModifier) {
			t.Errorf("Build(%q): error must wrap ErrUnsupportedModifier, got %v", mods, err)
		}
	}
}

func TestBuildRejectsInvalidRegex(t *testing.T) {
	if _, err := Build([]string{"re"}, []event.Value{event.String("(")}); err == nil {
		t.Fatal("an invalid regex must be an error")
	}
}

func TestBuildRejectsNoValuesAndListValues(t *testing.T) {
	if _, err := Build(nil, nil); err == nil {
		t.Fatal("no values must be an error")
	}
	if _, err := Build(nil, []event.Value{event.List(event.String("a"))}); err == nil {
		t.Fatal("a list is not a scalar detection value")
	}
}

func TestBuildNullValue(t *testing.T) {
	m, err := Build(nil, []event.Value{event.Null()})
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.Null()) {
		t.Fatal("a null value builds a null matcher")
	}
	if hit(t, m, event.String("")) {
		t.Fatal("null does not match an empty string")
	}
}

func TestBuildIntValueComparesAsText(t *testing.T) {
	m, err := Build(nil, []event.Value{event.Int(4688)})
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.String("4688")) || !hit(t, m, event.Int(4688)) {
		t.Fatal("an int rule value compares by its decimal text")
	}
}

func TestBuildAllWithSingleValue(t *testing.T) {
	m := build(t, "contains|all", "alpha")
	if !hit(t, m, event.String("xxalphaxx")) || hit(t, m, event.String("beta")) {
		t.Fatal("all over one value is a plain contains")
	}
}

func TestBuildAllWithoutComparison(t *testing.T) {
	m := build(t, "all", "a", "b")
	if hit(t, m, event.String("a")) {
		t.Fatal("all with equals over a scalar cannot satisfy two different values")
	}
	if !hit(t, m, event.List(event.String("a"), event.String("b"))) {
		t.Fatal("all with equals is satisfied by a list holding every value")
	}
}

func TestBuildModifierOrderDoesNotMatter(t *testing.T) {
	a := build(t, "contains|all", "alpha", "beta")
	b := build(t, "all|contains", "alpha", "beta")
	c := build(t, "i|re", "^alpha")
	for _, in := range []string{"alpha beta", "beta", "ALPHA"} {
		if hit(t, a, event.String(in)) != hit(t, b, event.String(in)) {
			t.Fatalf("contains|all and all|contains differ on %q", in)
		}
	}
	if !hit(t, c, event.String("ALPHA")) {
		t.Fatal("i|re is the same as re|i")
	}
}

func TestBuildRegexInList(t *testing.T) {
	m := build(t, "re", "^a", "b$")
	if !hit(t, m, event.String("xb")) || hit(t, m, event.String("xbx")) {
		t.Fatal("a regex list is an OR of compiled patterns")
	}
	if _, err := Build([]string{"re"}, []event.Value{event.String("ok"), event.String("(")}); err == nil {
		t.Fatal("an invalid regex anywhere in the list must be an error")
	}
}

func TestBuildBoolValueComparesAsText(t *testing.T) {
	m, err := Build(nil, []event.Value{event.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	if !hit(t, m, event.String("TRUE")) || !hit(t, m, event.Bool(true)) || hit(t, m, event.Bool(false)) {
		t.Fatal("a bool rule value compares by its text")
	}
}

func TestBuildRejectsNullWithComparison(t *testing.T) {
	for _, mods := range []string{"contains", "startswith", "endswith", "re"} {
		_, err := Build([]string{mods}, []event.Value{event.Null()})
		if err == nil || !errors.Is(err, ErrUnsupportedModifier) {
			t.Errorf("Build(%q, null): want ErrUnsupportedModifier, got %v", mods, err)
		}
	}
}

func TestBuildListValueErrorNamesKind(t *testing.T) {
	_, err := Build(nil, []event.Value{event.List()})
	if err == nil || !strings.Contains(err.Error(), "list") {
		t.Fatalf("want an error naming the kind, got %v", err)
	}
}
