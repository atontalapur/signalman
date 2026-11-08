package match

import (
	"strings"
	"testing"
	"unicode/utf8"

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

func TestWildcardLiterals(t *testing.T) {
	cases := map[string][]string{
		`*\Cmd.EXE`:   {`\cmd.exe`},
		`a*b?cd*`:     {"a", "b", "cd"},
		`*`:           nil,
		`x\*y*z`:      {"x*y", "z"},
		`*\\*`:        {`\`},
		`ÄBC`:         {"äbc"},
		"plain":       {"plain"},
		"??":          nil,
		`trailing\`:   {`trailing\`},
		`esc\?\\done`: {`esc?\done`},
	}
	for pat, want := range cases {
		got := CompileWildcard(pat).Literals()
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("Literals(%q) = %q, want %q", pat, got, want)
		}
	}
}

// Every literal run of a pattern appears, folded, in every string the
// pattern matches. The prefilter's soundness rests on this.
func TestWildcardLiteralsAppearInEveryMatch(t *testing.T) {
	cases := []struct{ pat, s string }{
		{`*\cmd.exe`, `C:\Windows\CMD.EXE`},
		{`a*b?cd*`, "AxxxbQcdzz"},
		{`*ÄBC*`, "xxäbcxx"},
	}
	for _, c := range cases {
		w := CompileWildcard(c.pat)
		if !w.MatchString(c.s) {
			t.Fatalf("%q must match %q", c.pat, c.s)
		}
		folded := string(AppendFold(nil, c.s))
		for _, lit := range w.Literals() {
			if !strings.Contains(folded, lit) {
				t.Fatalf("literal %q of %q missing from %q", lit, c.pat, folded)
			}
		}
	}
}

// AppendFold is strings.ToLower with foldRune, which keeps a non-ASCII
// rune whose lowercase is ASCII (U+0130, U+212A) as itself.
func TestAppendFoldIsFold(t *testing.T) {
	for _, s := range []string{"", "abc", "ABC", `C:\Windows`, "ÄÖÜ", "İstanbul", "\xff\xfeA", "a\xc3", "\u212a", "ẞ", "\uFFFD"} {
		got := AppendFold([]byte("prefix"), s)
		if want := strings.Map(foldRune, s); string(got) != "prefix"+want {
			t.Errorf("AppendFold(%q) = %q, want %q", s, got[6:], want)
		}
	}
	if got := Fold("İstanbul"); got != "İstanbul" {
		t.Errorf("Fold(İstanbul) = %q: the dotted capital I must not become i", got)
	}
}

func FuzzAppendFold(f *testing.F) {
	for _, s := range []string{"", "ABC", "ÄÖÜ", "\xff", "a\xc3(", "İ"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := AppendFold(nil, s)
		if want := strings.Map(foldRune, s); string(got) != want {
			t.Fatalf("AppendFold(%q) = %q, want %q", s, got, want)
		}
		if !strings.ContainsAny(s, "\u0130\u212a") && string(got) != strings.ToLower(s) {
			t.Fatalf("AppendFold(%q) = %q differs from strings.ToLower away from U+0130 and U+212A", s, got)
		}
		if !utf8.Valid(got) && utf8.ValidString(strings.ToLower(s)) {
			t.Fatalf("AppendFold(%q) is not valid UTF-8", s)
		}
	})
}

// FuzzWildcardLiterals checks the prefilter's premise directly: a pattern
// that matches a string has every one of its literal runs inside the folded
// string.
func FuzzWildcardLiterals(f *testing.F) {
	f.Add(`*\cmd.exe`, `C:\CMD.EXE`)
	f.Add(`a*b?c`, "aXbYc")
	f.Add(`x\*y*`, "x*yzz")
	f.Fuzz(func(t *testing.T, pat, s string) {
		w := CompileWildcard(pat)
		if !w.MatchString(s) {
			return
		}
		folded := string(AppendFold(nil, s))
		for _, lit := range w.Literals() {
			if !strings.Contains(folded, lit) {
				t.Fatalf("pattern %q matches %q but literal %q is not in %q", pat, s, lit, folded)
			}
		}
	})
}
