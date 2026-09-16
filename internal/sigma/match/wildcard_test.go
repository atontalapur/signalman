package match

import "testing"

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
	if HasWildcard(`a\*b`) || HasWildcard("ab") {
		t.Fatal("escaped star and plain text are not wildcards")
	}
}

func FuzzWildcard(f *testing.F) {
	f.Add("a*b", "aXb")
	f.Add(`a\*b`, "a*b")
	f.Fuzz(func(t *testing.T, pat, in string) {
		_ = CompileWildcard(pat).MatchString(in)
	})
}
