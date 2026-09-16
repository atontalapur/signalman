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
