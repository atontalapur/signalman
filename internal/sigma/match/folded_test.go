package match

import "testing"

var foldedCases = []struct {
	pat, s string
}{
	{"cmd.exe", "CMD.EXE"},
	{"cmd.exe", "cmd.exe.bak"},
	{`*\cmd.exe`, `C:\Windows\CMD.exe`},
	{`*\cmd.exe`, `cmd.exe`},
	{`C:\*`, `c:\windows`},
	{`*comsvcs*`, "rundll32 COMSVCS.dll"},
	{`*comsvcs*`, "rundll32"},
	{"a?c", "abc"},
	{"a?c", "aéc"},
	{"a?c", "ac"},
	{"*a*b*", "xxaYYbzz"},
	{"*a*b*", "xxbYYazz"},
	{"*", ""},
	{"**", "abc"},
	{"", ""},
	{"", "x"},
	{`x\*y`, "x*y"},
	{`x\*y`, "xay"},
	{"*ÄBC*", "--äbc--"},
	{"?", "\xff"},
	{"*\uFFFD*", "a\xffb"},
	{"İ*", "i̇x"},
}

func TestFoldedAgreesWithMatchString(t *testing.T) {
	for _, c := range foldedCases {
		w := CompileWildcard(c.pat)
		want := w.MatchString(c.s)
		if got := w.Folded().Match(AppendFold(nil, c.s)); got != want {
			t.Errorf("pattern %q on %q: folded %v, MatchString %v", c.pat, c.s, got, want)
		}
	}
}

func FuzzFoldedAgreesWithMatchString(f *testing.F) {
	for _, c := range foldedCases {
		f.Add(c.pat, c.s)
	}
	f.Fuzz(func(t *testing.T, pat, s string) {
		w := CompileWildcard(pat)
		want := w.MatchString(s)
		if got := w.Folded().Match(AppendFold(nil, s)); got != want {
			t.Fatalf("pattern %q on %q: folded %v, MatchString %v", pat, s, got, want)
		}
	})
}

func BenchmarkFoldedContains(b *testing.B) {
	f := CompileWildcard("*comsvcs*").Folded()
	in := AppendFold(nil, `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\t.dmp full`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f.Match(in)
	}
}
