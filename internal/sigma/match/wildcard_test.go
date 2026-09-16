package match

import (
	"strings"
	"testing"
)

func TestWildcard(t *testing.T) {
	cases := []struct {
		pat, in string
		want    bool
	}{
		{"abc", "abc", true},
		{"abc", "ABC", true},
		{"abc", "abcd", false},
		{"*abc", "xxabc", true},
		{"abc*", "abcxx", true},
		{"*abc*", "xxabcxx", true},
		{"*", "", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{`a\*c`, "a*c", true},
		{`a\*c`, "abc", false},
		{`a\?c`, "a?c", true},
		{`a\?c`, "abc", false},
		{"**a", "xa", true},
		{"a*", "", false},
		{`a\\c`, `a\c`, true},
		// Sigma escaping: a wildcard after a path separator needs \\*,
		// since \* is a literal asterisk.
		{`C:\Windows\\*\rundll32.exe`, `C:\Windows\System32\rundll32.exe`, true},
		{`C:\Windows\*\rundll32.exe`, `C:\Windows\System32\rundll32.exe`, false},
		{`C:\Windows\*\rundll32.exe`, `C:\Windows*\rundll32.exe`, true},
		// The spec's escape table, one row each.
		{`a\b`, `a\b`, true},
		{`a\*`, `a*`, true},
		{`a\\*`, `a\xyz`, true},
		{`a\\\*`, `a\*`, true},
		{`a\\\*`, `a\x`, false},
		{`a\\\\`, `a\\`, true},
		{"*.*.*.*", "1.2.3.4", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXcYYb", false},
		// A regex metacharacter is a literal here. This is the reason the
		// matcher exists instead of a translation to regex.
		{"cmd.exe (x86)", "cmd.exe (x86)", true},
		{"c+d", "ccccd", false},
		// A literal mismatch before any star fails without backtracking.
		{"a?c", "xbc", false},
		{"abc*", "xbc", false},
		// ? needs one rune of input; it does not match end of input.
		{"ab?", "ab", false},
		{"ab?", "abc", true},
		{"?", "", false},
		// A run of trailing stars matches the empty tail.
		{"a**", "a", true},
		{"a**", "axyz", true},
		{"", "", true},
		{"", "a", false},
		// A backslash at the end of the pattern is a literal backslash.
		{`a\`, `a\`, true},
		{`a\`, `a`, false},
		// Wildcards work on runes, not bytes.
		{"?", "é", true},
		{"caf?", "café", true},
		{"café", "CAFÉ", true},
	}
	for _, c := range cases {
		t.Run(c.pat+"|"+c.in, func(t *testing.T) {
			if got := CompileWildcard(c.pat).MatchString(c.in); got != c.want {
				t.Fatalf("CompileWildcard(%q).MatchString(%q) = %v want %v", c.pat, c.in, got, c.want)
			}
		})
	}
}

func TestHasWildcard(t *testing.T) {
	if !HasWildcard("a*b") || !HasWildcard("a?b") {
		t.Fatal("expected wildcards to be detected")
	}
	if HasWildcard(`a\*b`) || HasWildcard(`a\?b`) || HasWildcard("ab") {
		t.Fatal("escaped star and plain text are not wildcards")
	}
}

func FuzzWildcard(f *testing.F) {
	f.Add("a*b", "aXb")
	f.Add(`a\*b`, "a*b")
	f.Fuzz(func(t *testing.T, pat, in string) {
		_ = CompileWildcard(pat).MatchString(in)
		// Properties with a cheap oracle: a string matches its own escaped
		// form, a lone star matches everything, and *s* finds s.
		if !CompileWildcard(escapeAll(pat)).MatchString(pat) {
			t.Fatalf("escaped %q does not match itself", pat)
		}
		if !CompileWildcard("*").MatchString(in) {
			t.Fatalf("* does not match %q", in)
		}
		if !CompileWildcard("*" + escapeAll(in) + "*").MatchString(in) {
			t.Fatalf("*%q* does not match itself", in)
		}
	})
}

// escapeAll turns s into a pattern that matches exactly s.
func escapeAll(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`)
	return r.Replace(s)
}
