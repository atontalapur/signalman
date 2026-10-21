package match

import (
	"strings"
	"testing"

	"github.com/atontalapur/signalman/internal/event"
)

func plan(t *testing.T, mods string, vals ...event.Value) Spec {
	t.Helper()
	var ms []string
	if mods != "" {
		ms = strings.Split(mods, "|")
	}
	s, err := Plan(ms, vals)
	if err != nil {
		t.Fatalf("Plan(%q): %v", mods, err)
	}
	return s
}

func TestPlanStringComparisonsBecomePatterns(t *testing.T) {
	cases := []struct {
		mods, val string
		want      []string
	}{
		{"", `C:\x.exe`, []string{`C:\x.exe`}},
		{"contains", "abc", []string{"*abc*"}},
		{"startswith", `C:\`, []string{`C:\\*`}},
		{"endswith", `\cmd.exe`, []string{`*\cmd.exe`}},
		{"contains|windash", "-a", nil}, // windash after the comparison is still a transform
		{"windash|contains", " -a", []string{"* -a*", "* /a*", "* –a*", "* —a*", "* ―a*"}},
		{"base64|contains", "ab", []string{"*" + Base64("ab") + "*"}},
	}
	for _, c := range cases {
		s := plan(t, c.mods, event.String(c.val))
		if len(s.Values) != 1 || s.Values[0].Kind != SpecPattern {
			t.Fatalf("%q: spec = %+v", c.mods, s)
		}
		if c.want == nil {
			continue
		}
		got := s.Values[0].Patterns
		if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Fatalf("%q %q: patterns = %q, want %q", c.mods, c.val, got, c.want)
		}
	}
}

func TestPlanKindsAndCombination(t *testing.T) {
	s := plan(t, "contains|all", event.String("a"), event.String("b"))
	if !s.All || len(s.Values) != 2 {
		t.Fatalf("all: %+v", s)
	}
	if plan(t, "", event.Null()).Values[0].Kind != SpecNull {
		t.Fatal("null")
	}
	if v := plan(t, "re|i", event.String("a.c")).Values[0]; v.Kind != SpecRegex || !v.Regex.MatchString("ABC") {
		t.Fatalf("re|i: %+v", v)
	}
	if v := plan(t, "cidr", event.String("10.1.2.3/8")).Values[0]; v.Kind != SpecCIDR || v.Prefix.String() != "10.0.0.0/8" {
		t.Fatalf("cidr: %+v", v)
	}
	if v := plan(t, "gte", event.String(" 7 ")).Values[0]; v.Kind != SpecCompare || v.Op != "gte" || v.N != 7 {
		t.Fatalf("gte: %+v", v)
	}
	if v := plan(t, "fieldref", event.String("Other")).Values[0]; v.Kind != SpecFieldRef || v.Field != "Other" {
		t.Fatalf("fieldref: %+v", v)
	}
}

func TestPlanRejectsWhatBuildRejects(t *testing.T) {
	for _, mods := range [][]string{{"contains", "endswith"}, {"i"}, {"base64", "re"}, {"bogus"}} {
		if _, err := Plan(mods, []event.Value{event.String("x")}); err == nil {
			t.Fatalf("Plan(%v) must fail", mods)
		}
		if _, err := Build(mods, []event.Value{event.String("x")}); err == nil {
			t.Fatalf("Build(%v) must fail", mods)
		}
	}
}
